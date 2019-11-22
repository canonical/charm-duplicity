"""
This is the collection of the duplicity charm's reactive scripts. It defines
functions used as callbacks to shape the charm's behavior during various state
change events such as relations being added, config values changing, relations
joining etc.

See the following for information about reactive charms:
  * https://jujucharms.com/docs/devel/developer-getting-started
  * https://github.com/juju-solutions/layer-basic#overview
"""

from lib_duplicity import DuplicityHelper
from charmhelpers.core import hookenv, host
from charms.reactive import set_flag, clear_flag, when_not, when
from charmhelpers import fetch

import os

helper = DuplicityHelper()


@when_not('duplicity.installed')
def install_duplicity():
    """
    Apt install duplicity's dependencies:
      - duplicity
      - python-paramiko for ssh
      - python-boto for aws

    :return:
    """
    hookenv.status_set("maintenance", "Installing duplicity")
    fetch.apt_install("duplicity")
    fetch.apt_install("python-paramiko")
    fetch.apt_install("python-boto")
    hookenv.status_set('active', '')
    set_flag('duplicity.installed')


@when('config.set.backend')
@when('config.set.remote_backup_url')
def validate_backend():
    """
    Validates that the config value for 'backend' is something that duplicity
    can use (see config description for backend for the accepted types). For S3
    only, check that the AWS IMA credentials are also set.
    """
    backend = hookenv.config().get("backend").lower()
    if backend not in ["s3", "ssh", "scp", "sftp", "ftp", "rsync", "file"]:
        hookenv.status_set('blocked',
                           'Unrecognized backend "{}"'.format(backend))
        return False
    elif backend == "s3":
        # make sure 'aws_access_key_id' and 'aws_secret_access_key' exist
        if not hookenv.config().get("aws_access_key_id") and \
                not hookenv.config().get("aws_secret_access_key"):
            hookenv.status_set('blocked', 'S3 backups require \
"aws_access_key_id" and "aws_secret_access_key" to be set')
            return False
    if not hookenv.config().get("remote_backup_url"):
        # remote url is unset
        hookenv.status_set('blocked', 'Backup path is required. Set config \
for "remote_backup_url"')
        return False
    return True


@when('config.set.aux_backup_directory')
def create_aux_backup_directory():
    aux_backup_dir = hookenv.config().get("aux_backup_directory")
    if aux_backup_dir:
        # if the data is not ok to make a directory path then let juju catch it
        if not os.path.exists(aux_backup_dir):
            os.makedirs(aux_backup_dir)
            hookenv.log("Creating auxiliary backup directory: {}".format(
                aux_backup_dir))


@when('config.set.backup_frequency')
def validate_cron_frequency():
    cron_frequency = hookenv.config().get("backup_frequency").lower()
    if cron_frequency not in ["daily", "weekly", "monthly", "manual", "auto"]:
        hookenv.status_set('blocked',
                           'Unknown value "{}" for cron frequency'.format(
                               cron_frequency)
                           )
        return False
    return True


@when('config.set.encryption_passphrase')
@when('config.set.gpg_public_key')
@when('config.set.disable_encryption')
def validate_encryption_method():
    """
    Function to check that a viable encryption method is configured.
    """
    passphrase = hookenv.config().get("encryption_passphrase")
    gpg_key = hookenv.config().get("gpg_public_key")
    disable = hookenv.config().get("disable_encryption")
    if not passphrase and not gpg_key and not disable:
        hookenv.status_set('blocked', 'Must set either an encryption \
passphrase, GPG public key, or disable encryption')
        return False
    return True


@when('config.changed')
def validate_configs():
    hookenv.status_set("maintenance", "Configuring Duplicity")
    clear_flag('duplicity.configured')
    valid = validate_backend() and \
        validate_cron_frequency() and \
        validate_encryption_method()

    if valid:
        set_flag('duplicity.configured')


@when('duplicity.configured')
def update_cron():
    """
    Finalizes the backup cron script when duplicity has been configured
    successfully. The cron script will be a call to juju run-action do-backup
    """
    hookenv.status_set('active', 'Rendering duplicity crontab')
    helper.render_backup_cron()
    hookenv.status_set('active', 'Ready.')