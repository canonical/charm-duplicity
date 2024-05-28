"""Duplicity juju actions."""

import os
import subprocess
from urllib.parse import urlparse

from charmhelpers.core import hookenv, templating

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_ssh_private_key,
)


from fabric import Connection

BACKUP_CRON_FILE = "/etc/cron.d/periodic_backup"
DELETION_CRON_FILE = "/etc/cron.d/periodic_deletion"
CRON_LOG_PATH = "/var/log/duplicity"
ROOT_KNOWN_HOSTS_PATH = "/root/.ssh/known_hosts"
PRIVATE_SSH_KEY_PATH = "/root/.ssh/duplicity_id_rsa"


def safe_remove_backup_cron():
    """Delete backup crontab."""
    if os.path.exists(BACKUP_CRON_FILE):
        hookenv.log("Removing backup cron file.", level=hookenv.DEBUG)
        os.remove(BACKUP_CRON_FILE)
        hookenv.log("Backup cron file removed.", level=hookenv.DEBUG)


def safe_remove_deletion_cron():
    """Delete deletion crontab."""
    if os.path.exists(DELETION_CRON_FILE):
        hookenv.log("Removing deletion cron file.", level=hookenv.DEBUG)
        os.remove(DELETION_CRON_FILE)
        hookenv.log("Deletion cron file removed.", level=hookenv.DEBUG)


class DuplicityHelper:
    """Actual juju actions handler."""

    def __init__(self):
        """Introduce configurations."""
        self.charm_config = hookenv.config()

    def _build_cmd(self, duplicity_command, *args):
        """Duplicity command builder."""
        cmd = ["duplicity", duplicity_command]
        cmd.extend([str(arg) for arg in args])
        cmd.append(self._backup_url())
        cmd.extend(self._additional_options())
        if "remove" in duplicity_command:
            cmd.append("--force")
        return cmd

    def _executor(self, cmd):
        self._set_environment_vars()
        self.safe_log("Duplicity Command: {}".format(cmd))
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)

    def _backup_url(self):
        """Remote URL.

        Helper function to assemble the backup url into a format accepted
        by duplicity, based off of the 'backend' and 'remote_backup_url'
        defined in the charm config. _backup_url will be appended with the
        charms unit name
        """
        backend = self.charm_config.get("backend").lower()
        prefix = "{}://".format(backend)
        remote_path = self.charm_config.get("remote_backup_url")

        # start building the url
        url = ""

        if backend in ["rsync", "scp", "ftp", "sftp"]:
            # These all require SSH Type Authentication and will attempt to use
            # the provided remote host credentials
            user = self.charm_config.get("remote_user")
            password = self.charm_config.get("remote_password")
            if user:
                if password:
                    url += "{}:{}@".format(user, password)
                else:
                    url += "{}@".format(user)
            url += remote_path.replace(prefix, "")
        elif backend in ["s3", "file", "azure"]:
            url = remote_path.replace(prefix, "")
        else:
            return None

        url = (
            "{}://".format(backend)
            + url  # noqa: W503
            + "/{}".format(hookenv.local_unit().replace("/", "-"))  # noqa: W503
        )

        return url

    def _set_environment_vars(self):
        """Environment vars.

        Helper function sets the required environmental variables used by
        duplicity.
        :return:
        """
        # Set the Azure Credentials. It doesnt matter if they are used or not
        os.environ["AZURE_CONNECTION_STRING"] = self.charm_config.get(
            "azure_connection_string"
        )
        os.environ["PASSPHRASE"] = self.charm_config.get("encryption_passphrase")

        # Set the Aws Credentials. It doesnt matter if they are used or not
        os.environ["AWS_SECRET_ACCESS_KEY"] = self.charm_config.get(
            "aws_secret_access_key"
        )
        os.environ["AWS_ACCESS_KEY_ID"] = self.charm_config.get("aws_access_key_id")
        os.environ["PASSWORD"] = self.charm_config.get("encryption_passphrase")

    def _additional_options(self):
        """Additional options to add to the duplicity cmd.

        Parses the config options and provides a list of args to be passed to
        duplicity, and useful for multiple duplicity actions.
        :return:
        """
        # backups named after the unit
        cmd = []

        if self.charm_config.get("private_ssh_key"):
            if self.charm_config.get("backend") == "rsync":
                cmd.append(
                    '--rsync-options=-e "ssh -i {}"'.format(PRIVATE_SSH_KEY_PATH)
                )
            else:
                cmd.append(
                    "--ssh-options=-oIdentityFile={}".format(PRIVATE_SSH_KEY_PATH)
                )

        if self.charm_config.get("disable_encryption"):
            cmd.append("--no-encryption")
        elif self.charm_config.get("gpg_public_key"):
            cmd.append(
                "--encrypt-key={}".format(self.charm_config.get("gpg_public_key"))
            )
        return cmd

    def setup_backup_cron(self):
        """Prepare the backup cron to run on the unit.

        Renders the cron and ensures logging directory exists.
        """
        if not os.path.exists(CRON_LOG_PATH):
            os.mkdir(CRON_LOG_PATH)
        self._render_backup_cron()

    def setup_deletion_cron(self):
        """Prepare the deletion cron to run on the unit.

        Renders the cron and ensures logging directory exists.
        """
        if not os.path.exists(CRON_LOG_PATH):
            os.mkdir(CRON_LOG_PATH)
        self._render_deletion_cron()

    def _render_backup_cron(self):
        """Render backup cron."""
        backup_frequency = self.charm_config.get("backup_frequency")
        if backup_frequency in ["hourly", "daily", "weekly", "monthly"]:
            backup_frequency = "@{}".format(backup_frequency)
        is_juju3 = subprocess.getoutput("ls /usr/bin/ | grep juju-exec")
        if is_juju3:
            juju_binary = "juju-exec"
        else:
            juju_binary = "juju-run"
        cron_ctx = {
            "frequency": backup_frequency,
            "unit_name": hookenv.local_unit(),
            "charm_dir": hookenv.charm_dir(),
            "juju_command": juju_binary,
        }
        templating.render("periodic_backup", BACKUP_CRON_FILE, cron_ctx)
        with open(BACKUP_CRON_FILE, "a") as cron_file:
            cron_file.write("\n")

    def _render_deletion_cron(self):
        """Render periodic deletion cron."""
        # Purposefully render hourly or daily crons a little before the
        # hour or day mark, to prevent the scenario (to an extent) of ending up with
        # one less backup and instead having one extra backup.
        deletion_frequency = self.charm_config.get("deletion_frequency")
        if deletion_frequency == "hourly":
            deletion_frequency = "40 * * * *"
        elif deletion_frequency == "daily":
            deletion_frequency = "0 23 * * *"
        is_juju3 = subprocess.getoutput("ls /usr/bin/ | grep juju-exec")
        if is_juju3:
            juju_binary = "juju-exec"
        else:
            juju_binary = "juju-run"
        cron_ctx = {
            "frequency": deletion_frequency,
            "unit_name": hookenv.local_unit(),
            "charm_dir": hookenv.charm_dir(),
            "juju_command": juju_binary,
        }
        templating.render("periodic_deletion", DELETION_CRON_FILE, cron_ctx)
        with open(DELETION_CRON_FILE, "a") as cron_file:
            cron_file.write("\n")

    @staticmethod
    def update_known_host_file(known_host_key):
        """Update known host file."""
        permissions = "a+" if os.path.exists(ROOT_KNOWN_HOSTS_PATH) else "w+"
        with open(ROOT_KNOWN_HOSTS_PATH, permissions) as known_host_file:
            contents = known_host_file.read()
            if known_host_key not in contents:
                print(known_host_key, file=known_host_file)

    def do_backup(self, **kwargs):
        """Execute the backup call to duplicity as configured by the charm.

        :param: kwargs
        :type: dictionary of values that may be used instead of config values
        """
        cmd = self._build_cmd("full", self.charm_config.get("aux_backup_directory"))
        if self.charm_config.get("backend") == "rsync":
            self.create_remote_dirs()
        return self._executor(cmd)

    def do_deletion(self, **kwargs):
        """Execute the deletion call to duplicity as configured by the charm.

        :param: kwargs
        :type: dictionary of values that may be used instead of config values
        """
        rp = self.charm_config.get("retention_period")
        if rp[-1] == "d":
            rp = rp[:-1] + "D"
        return self.remove_older_than(time=rp)

    def safe_log(self, message, level=hookenv.INFO):
        """Replace password in the log with ***."""
        password = self.charm_config.get("remote_password")
        if password and password in message:
            message = message.replace(password, "*****")
        hookenv.log(message=message, level=level)

    def create_remote_dirs(self):
        """Create remote dirs when using rsync backend."""
        parsed_url = urlparse(self._backup_url())
        at_index = parsed_url.netloc.find("@")
        if at_index:
            host = parsed_url.netloc[at_index + 1 :]  # noqa: E203
        else:
            host = parsed_url.netloc
        conn = Connection(host=host)
        user = self.charm_config.get("remote_user")
        ssh_key_exists = self.charm_config.get("private_ssh_key")
        if user:
            conn.user = user
        if ssh_key_exists:
            conn.connect_kwargs = dict(key_filename=PRIVATE_SSH_KEY_PATH)
        conn.run(
            "mkdir -p {}/{}".format(
                parsed_url.path[1:], hookenv.local_unit().replace("/", "-")
            )
        )

    def cleanup(self):
        # TODO
        # duplicity cleanup <target_url>
        """Delete the extraneous duplicity files on the given backend."""
        raise NotImplementedError()

    def verify(self):
        # TODO
        # duplicity verify <target_url> <source_dir>
        """Restore backup contents.

        Restore temporarily file by file and compare against the local path’s contents
        """
        raise NotImplementedError()

    def collection_status(self):
        # TODO
        # duplicity collection-status <target_url>
        """Summarize the status of the backup repository.

        List the status by printing the chains and sets found,
        and the number of volumes in each
        """
        raise NotImplementedError()

    def list_current_files(self, **kwargs):
        """Duplicity list current files in the remote directory.

        :param: kwargs
        :type: dictionary of values that may be used instead of config values
        """
        cmd = self._build_cmd("list-current-files")
        return self._executor(cmd)

    def restore(self):
        # TODO
        # duplicity restore <source_url> <target_dir>
        """Restore the full monty or selected folders/files."""
        raise NotImplementedError()

    def remove_older_than(self, time):
        """Delete all backup sets older than the given time.

        :param: kwargs
        :type: dictionary of values that may be used instead of config values
            - used types from kwargs: time
        """
        cmd = self._build_cmd("remove-older-than", time)
        return self._executor(cmd)

    def remove_all_but_n_full(self, count):
        """Keep the last count full backups and associated incremental sets.

        :param: kwargs
        :type: dictionary of values that may be used instead of config values
            - used types from kwargs: count
        """
        cmd = self._build_cmd("remove-all-but-n-full", count)
        return self._executor(cmd)

    def remove_all_inc_of_but_n_full(self, count):
        """Keep only old full backups and not their increments.

        :param: kwargs
        :type: dictionary of values that may be used instead of config values
            - used types from kwargs: count
        """
        cmd = self._build_cmd("remove-all-inc-of-but-n-full", count)
        return self._executor(cmd)

    def check_key_rsa_openssh(self, private_key):
        """Check if private key is both RSA and encoded with OpenSSH format."""
        try:
            # try loading an OpenSSH encoded key
            loaded_private_key = load_ssh_private_key(
                private_key.encode("utf-8"), password=None
            )
        except ValueError:
            # key is in PEM format
            return False
        return isinstance(loaded_private_key, rsa.RSAPrivateKey)

    def convert_key_to_pem(self, private_key):
        """Convert private key from OpenSSH to PEM format."""
        private_key_openssh = load_ssh_private_key(
            private_key.encode("utf-8"), password=None
        )
        private_key_pem = private_key_openssh.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        return private_key_pem.decode()
