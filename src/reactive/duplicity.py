"""This is the collection of the duplicity charm's reactive scripts.

It defines functions used as callbacks to shape the charm's behavior
during various state change events such as relations being added,
config values changing, relations joining etc.

See the following for information about reactive charms:
  * https://jujucharms.com/docs/devel/developer-getting-started
  * https://github.com/juju-solutions/layer-basic#overview
"""

import base64
import binascii
import os
import subprocess
from re import fullmatch

from charmhelpers import fetch
from charmhelpers.contrib.charmsupport.nrpe import NRPE
from charmhelpers.core import hookenv, host

from charms.reactive import (
    clear_flag,
    hook,
    is_flag_set,
    set_flag,
    when,
    when_any,
    when_not,
)

import croniter

from lib_duplicity import DuplicityHelper
from lib_duplicity import safe_remove_backup_cron, safe_remove_deletion_cron

PRIVATE_SSH_KEY_PATH = "/root/.ssh/duplicity_id_rsa"
PLUGINS_DIR = "/usr/local/lib/nagios/plugins/"

helper = DuplicityHelper()
config = hookenv.config()


def install_in_system_python(package_to_install):
    """Install dependency in system python.

    The charm use subprocess to call duplicity,
    which is installed by apt.
    So the azure-storage-blob has to be installed n system level python
    """
    subprocess.run(["sudo", "pip", "install", package_to_install])


@when_not("duplicity.installed")
def install_duplicity():
    """Apt install duplicity's dependencies.

    include:
      - duplicity
      - python-paramiko for ssh
      - python-boto for aws

    :return:
    """
    hookenv.status_set("maintenance", "Installing duplicity")
    fetch.apt_install("duplicity")
    fetch.apt_install("python-paramiko")
    fetch.apt_install("python-boto")
    fetch.apt_install("lftp")
    install_in_system_python("azure-storage-blob")
    hookenv.status_set("active", "")
    set_flag("duplicity.installed")


@hook("upgrade-charm")
def upgrade_duplicity():
    """If charm is refreshed it will install the packages which includes azure."""
    install_duplicity()


@when_any(
    "config.changed.backend",
    "config.changed.aws_access_key_id",
    "config.changed.aws_secret_access_key" "config.changed.known_host_key",
    "config.changed.azure_connection_string",
    "config.changed.remote_password",
    "config.changed.private_ssh_key",
)
def validate_backend():
    """Supported backends.

    Validates that the config value for 'backend' is something that duplicity
    can use (see config description for backend for the accepted types). For S3
    only, check that the AWS IMA credentials are set. For AZURE check connections
    string is also set.
    """
    backend = config.get("backend").lower()
    if backend in ["s3", "scp", "sftp", "ftp", "rsync", "file", "azure"]:
        clear_flag("duplicity.invalid_backend")
    else:
        set_flag("duplicity.invalid_backend")
        return
    if backend == "s3":
        if all([config.get("aws_access_key_id"), config.get("aws_secret_access_key")]):
            clear_flag("duplicity.invalid_aws_creds")
        else:
            set_flag("duplicity.invalid_aws_creds")
            return
    elif backend == "azure":
        if config.get("azure_connection_string"):
            clear_flag("duplicity.invalid_azure_creds")
        else:
            set_flag("duplicity.invalid_azure_creds")
            return
    elif backend == "rsync":
        if config.get("private_ssh_key"):
            clear_flag("duplicity.invalid_rsync_key")
        else:
            set_flag("duplicity.invalid_rsync_key")
            return
    if backend in ["scp", "rsync", "sftp"]:
        if config.get("known_host_key") and any(
            [config.get("remote_password"), config.get("private_ssh_key")]
        ):
            clear_flag("duplicity.invalid_secure_backend_opts")
        else:
            set_flag("duplicity.invalid_secure_backend_opts")
            return


@when("config.changed.known_host_key")
def update_known_host_key():
    """If known_host_key is set in the config, update known_host file."""
    known_host_key = config.get("known_host_key")
    if known_host_key:
        hookenv.status_set(
            workload_state="maintenance", message="Updating known_host_key"
        )
        helper.update_known_host_file(known_host_key)


@when("config.changed.remote_backup_url")
def check_remote_backup_url():
    """When backup url is set, clear invalid_backend flag."""
    if config.get("remote_backup_url"):
        clear_flag("duplicity.invalid_backend")
    else:
        set_flag("duplicity.invalid_backend")


@when("config.changed.aux_backup_directory")
def create_aux_backup_directory():
    """Create aux_backup_directory."""
    aux_backup_dir = config.get("aux_backup_directory")
    if aux_backup_dir:
        # if the data is not ok to make a directory path then let juju catch it
        if not os.path.exists(aux_backup_dir):
            os.makedirs(aux_backup_dir)
            hookenv.log("Created auxiliary backup directory: {}".format(aux_backup_dir))


@when("config.changed.backup_frequency")
def validate_cron_frequency():
    """Check how the backup frequency is configured.

    If goes with manual, do not create crontab.
    Otherwise create a crontab to do the backup.
    """
    cron_frequency = config.get("backup_frequency").lower()
    no_cron_options = ["manual"]
    create_cron_options = ["hourly", "daily", "weekly", "monthly"]
    if cron_frequency in no_cron_options:
        set_flag("duplicity.remove_backup_cron")
    elif cron_frequency in create_cron_options:
        set_flag("duplicity.create_backup_cron")
    else:
        try:
            croniter.croniter(cron_frequency)
            set_flag("duplicity.create_backup_cron")
        except (
            croniter.CroniterBadCronError,
            croniter.CroniterBadDateError,
            croniter.CroniterNotAlphaError,
        ):
            set_flag("duplicity.invalid_backup_frequency")
            clear_flag("duplicity.create_backup_cron")
            return
    clear_flag("duplicity.invalid_backup_frequency")


def is_valid_retention_period(retention_period):
    """Check if retention period is valid.

    Valid options are: manual, <n>d, <n>h for n days or n hours, bot not both.
    n must be an interger > 0.
    """
    return bool(fullmatch(r"(manual|[1-9]\d*[dh])", retention_period))


def is_valid_deletion_frequency(cron_frequency):
    """Check if deletion frequency is valid.

    Valid options are: hourly, daily, and any valid cron string.
    """
    if cron_frequency in ["hourly", "daily"]:
        return True
    return croniter.croniter.is_valid(cron_frequency)


@when_any(
    "config.changed.retention_period",
    "config.changed.deletion_frequency",
)
def validate_retention_policy():
    """Check what retention period and deletion frequency are configured to.

    If any one of the two configs are erroneous, do not create deletion cron.
    Otherwise create a crontab to do the deletion of backups.
    """
    retention_period = config.get("retention_period")
    if not is_valid_retention_period(retention_period):
        set_flag("duplicity.remove_deletion_cron")
        set_flag("duplicity.invalid_retention_period")
        return
    # important to clear invalid_retention_period here, otherwise the unit
    # can think it is still blocked on invalid retention period when it
    # should not be
    clear_flag("duplicity.invalid_retention_period")
    if retention_period == "manual":
        set_flag("duplicity.remove_deletion_cron")
        clear_flag("duplicity.invalid_deletion_frequency")
        return
    # retention period is valid and not manual
    # now check the validity of deletion frequency
    if not is_valid_deletion_frequency(config.get("deletion_frequency")):
        set_flag("duplicity.remove_deletion_cron")
        set_flag("duplicity.invalid_deletion_frequency")
        return
    clear_flag("duplicity.invalid_deletion_frequency")
    # Now both retention and frequency are valid
    set_flag("duplicity.create_deletion_cron")


@when_any(
    "config.changed.encryption_passphrase",
    "config.changed.gpg_public_key",
    "config.changed.disable_encryption",
)
def validate_encryption_method():
    """Check that if a viable encryption method is configured."""
    passphrase = config.get("encryption_passphrase")
    gpg_key = config.get("gpg_public_key")
    disable = config.get("disable_encryption")
    if any([passphrase, gpg_key, disable]):
        clear_flag("duplicity.invalid_encryption_method")
    else:
        set_flag("duplicity.invalid_encryption_method")


@when("duplicity.installed")
def check_status():
    """Check the current configuration status."""
    hookenv.atexit(assess_status)


def assess_status():  # pylint: disable=C901
    """All the possible status."""
    if is_flag_set("duplicity.invalid_remote_backup_url"):
        hookenv.status_set(
            workload_state="blocked",
            message='Backup path is required. Set config for "remote_backup_url"',
        )
        return
    if is_flag_set("duplicity.invalid_backend"):
        hookenv.status_set(
            workload_state="blocked",
            message='Unrecognized backend "{}"'.format(config.get("backend")),
        )
        return
    if is_flag_set("duplicity.invalid_aws_creds"):
        hookenv.status_set(
            workload_state="blocked",
            message='S3 backups require "aws_access_key_id" '
            'and "aws_secret_access_key" to be set',
        )
        return
    if is_flag_set("duplicity.invalid_azure_creds"):
        hookenv.status_set(
            workload_state="blocked",
            message='Azure backups require "azure_connection_string" ',
        )
        return
    if is_flag_set("duplicity.invalid_secure_backend_opts"):
        hookenv.status_set(
            workload_state="blocked",
            message="{} backend requires known_host_key "
            'and either "remote_password" or "private_ssh_key" '
            "to be set".format(config.get("backend")),
        )
        return
    if is_flag_set("duplicity.invalid_rsync_key"):
        hookenv.status_set(
            workload_state="blocked",
            message="rsync backend requires private_ssh_key. remote_password auth not "
            "supported",
        )
        return
    if is_flag_set("duplicity.invalid_encryption_method"):
        hookenv.status_set(
            workload_state="blocked",
            message="Must set either an encryption passphrase, GPG public key, or "
            "disable encryption",
        )
        return
    if is_flag_set("duplicity.invalid_private_ssh_key"):
        hookenv.status_set(
            workload_state="blocked",
            message="Invalid private_ssh_key. ensure that key is base64 encoded",
        )
        return
    if is_flag_set("duplicity.invalid_backup_frequency"):
        hookenv.status_set(
            workload_state="blocked",
            message='Invalid value "{}" for "backup_frequency"'.format(
                config.get("backup_frequency")
            ),
        )
        return
    if is_flag_set("duplicity.invalid_retention_period"):
        hookenv.status_set(
            workload_state="blocked",
            message='Invalid value "{}" for "retention_period"'.format(
                config.get("retention_period")
            ),
        )
        return
    if is_flag_set("duplicity.invalid_deletion_frequency"):
        hookenv.status_set(
            workload_state="blocked",
            message='Invalid value "{}" for "deletion_frequency"'.format(
                config.get("deletion_frequency")
            ),
        )
        return
    hookenv.status_set("active", "Ready")


@when("duplicity.create_backup_cron")
def create_backup_cron():
    """Create backup crontab.

    Finalizes the backup cron script when duplicity has been configured
    successfully. The cron script will be a call to juju run-action do-backup
    """
    hookenv.status_set("maintenance", "Rendering duplicity crontab")
    helper.setup_backup_cron()
    hookenv.status_set("active", "Rendered duplicity crontab")
    clear_flag("duplicity.create_backup_cron")


@when("duplicity.create_deletion_cron")
def create_deletion_cron():
    """Create deletion crontab.

    Finalizes the deletion cron script when duplicity has been configured
    successfully. The cron script will be a call to juju run-action remove-older-than
    """
    hookenv.status_set("maintenance", "Rendering duplicity crontab for deletion")
    helper.setup_deletion_cron()
    hookenv.status_set("active", "Rendered duplicity crontab for deletion")
    clear_flag("duplicity.create_deletion_cron")


@when("duplicity.remove_backup_cron")
def remove_backup_cron():
    """Remove backup crontab.

    Stops and removes the backup cron in case of duplicity not being configured
    correctly or manual option is set. The former ensures backups won't run
    under an incorrect config.
    """
    cron_backup_frequency = config.get("backup_frequency")
    hookenv.log(
        "Backup frequency set to {}. Skipping or removing cron setup.".format(
            cron_backup_frequency
        )
    )
    safe_remove_backup_cron()
    clear_flag("duplicity.remove_backup_cron")


@when("duplicity.remove_deletion_cron")
def remove_deletion_cron():
    """Remove deletion crontab.

    Stops and removes the deletion cron in case of duplicity not being configured
    correctly or manual option is set. The former ensures deletion won't run
    under an incorrect config.
    """
    retention_period = config.get("retention_period")
    cron_deletion_frequency = config.get("deletion_frequency")
    hookenv.log(
        "Retention period is set to {} and deletion frequency set to {}. \
            Skipping or removing cron setup.".format(
            retention_period, cron_deletion_frequency
        )
    )
    safe_remove_deletion_cron()
    clear_flag("duplicity.remove_deletion_cron")


@when("config.changed.private_ssh_key")
def update_private_ssh_key():
    """If configured to use private key, update it to PRIVATE_SSH_KEY_PATH."""
    private_key = config.get("private_ssh_key")
    if private_key:
        hookenv.status_set(
            workload_state="maintenance", message="Updating private ssh key"
        )
        try:
            decoded_private_key = base64.b64decode(private_key).decode("utf-8")
            ubuntu_release = host.lsb_release()["DISTRIB_CODENAME"]

            # python3-paramiko supports OpenSSH format keys only after v2.7
            # but the package version on both bionic and focal are below that.
            # Refer: https://packages.ubuntu.com/search?keywords=python3-paramiko
            # So OpenSSH format keys need to be converted to PEM format.
            if ubuntu_release in {"bionic", "focal"}:
                if helper.check_key_rsa_openssh(decoded_private_key):
                    hookenv.log(
                        "Detected an RSA private key encoded in OpenSSH format."
                    )
                    decoded_private_key = helper.convert_key_to_pem(decoded_private_key)
                    hookenv.log("Private key has been converted to PEM format.")
        except (UnicodeDecodeError, binascii.Error) as e:
            hookenv.log(
                "Failed to decode private key {} to utf-8 with error: {}.\n"
                "Not creating ssh key file".format(private_key, e),
                level=hookenv.ERROR,
            )
            set_flag("duplicity.invalid_private_ssh_key")
            return

        with open(PRIVATE_SSH_KEY_PATH, "w") as f:
            f.write(decoded_private_key)
        os.chmod(PRIVATE_SSH_KEY_PATH, 0o600)
    else:
        if os.path.exists(PRIVATE_SSH_KEY_PATH):
            os.remove(PRIVATE_SSH_KEY_PATH)
    clear_flag("duplicity.invalid_private_ssh_key")


@when("nrpe-external-master.available")
@when_not("nrpe-external-master.initial-config")
def initial_nrpe_config():
    """Initialize nrpe configurations when available."""
    set_flag("nrpe-external-master.initial-config")
    render_checks()


@when("nrpe-external-master.initial-config")
@when_any("config.changed.nagios_context", "config.changed.nagios_servicegroups")
def render_checks():
    """Add nrpe checks to check periodic backup status."""
    hookenv.log("Creating NRPE checks.")
    charm_plugin_dir = os.path.join(hookenv.charm_dir(), "scripts", "plugins/")
    if not os.path.exists(PLUGINS_DIR):
        os.makedirs(PLUGINS_DIR)
    host.rsync(charm_plugin_dir, PLUGINS_DIR)
    nrpe = NRPE()
    nrpe.add_check(
        check_cmd=os.path.join(PLUGINS_DIR, "check_backup_status.py"),
        shortname="backups",
        description="Check that periodic backups have not failed.",
    )
    nrpe.write()
    set_flag("nrpe-external-master.configured")
    hookenv.log("NRPE checks created.")


@when("nrpe-external-master.configured")
@when_not("nrpe-external-master.available")
def remove_nrpe_checks():
    """Delete nrpe checks."""
    nrpe = NRPE()
    nrpe.remove_check(shortname="backups")
    clear_flag("nrpe-external-master.configured")


@hook()
def stop():
    """Stop and removes the backup crontab.

    Stops and removes the backup cron in case of duplicity not being
    configured correctly or manual.
    """
    safe_remove_backup_cron()
    safe_remove_deletion_cron()
