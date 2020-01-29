import subprocess
import os

from charmhelpers.core import hookenv, templating


BACKUP_CRON_FILE = '/etc/cron.d/periodic_backup'
BACKUP_CRON_LOG_PATH = '/var/log/duplicity'
ROOT_KNOWN_HOSTS_PATH = '/root/.ssh/known_hosts'


def safe_remove_backup_cron():
    if os.path.exists(BACKUP_CRON_FILE):
        hookenv.log('Removing backup cron file.', level=hookenv.DEBUG)
        os.remove(BACKUP_CRON_FILE)
        hookenv.log('Backup cron file removed.', level=hookenv.DEBUG)


class DuplicityHelper():
    def __init__(self):
        self.charm_config = hookenv.config()

    @property
    def backup_cmd(self):
        cmd = ['duplicity']
        if self.charm_config.get('private_ssh_key'):
            cmd.append('--ssh-options=-oIdentityFile=/root/.ssh/duplicity_id_rsa')
        # later switch to cmd.append('full' if self.charm_config.get('full_backup') else 'incr')
        # when full_backup implemented
        cmd.append('full')
        cmd.extend([self.charm_config.get('aux_backup_directory'), self._backup_url()])
        cmd.extend(self._additional_options())
        return cmd

    @property
    def list_files_cmd(self):
        cmd = ['duplicity', 'list-current-files', self._backup_url()]
        cmd.extend(self._additional_options())
        return cmd

    def _backup_url(self):
        """
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

        if backend in ["rsync", "scp", "ssh", "ftp", "sftp"]:
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
        elif backend in ["s3", "file"]:
            url = remote_path.replace(prefix, "")
        else:
            return None

        url = "{}://".format(backend) + url + "/{}".format(
            hookenv.local_unit().replace("/", "-"))
        return url

    def _set_environment_vars(self):
        """
        Helper function sets the required environmental variables used by
        duplicity.
        :return:
        """
        # Set the Aws Credentials. It doesnt matter if they are used or not
        os.environ["AWS_SECRET_ACCESS_KEY"] = self.charm_config.get(
            "aws_secret_access_key")
        os.environ["AWS_ACCESS_KEY_ID"] = self.charm_config.get(
            "aws_access_key_id")
        os.environ["PASSWORD"] = self.charm_config.get(
            "encryption_passphrase")

    def _additional_options(self):
        """
        Parses the config options and provides a list of args to be passed to
        duplicity, and useful for multiple duplicity actions.
        :return:
        """
        # backups named after the unit
        cmd = []

        if self.charm_config.get("disable_encryption"):
            cmd.append("--no-encryption")
        elif self.charm_config.get("gpg_public_key"):
            cmd.append("--gpg-key={}".format(
                self.charm_config.get("gpg_public_key")))
        return cmd

    def setup_backup_cron(self):
        """
        Sets up the backup cron to run on the unit. Renders the cron and ensures logging
        directory exists.
        """
        if not os.path.exists(BACKUP_CRON_LOG_PATH):
            os.mkdir(BACKUP_CRON_LOG_PATH)
        self._render_backup_cron()

    def _render_backup_cron(self):
        """
        Render backup cron.
        """
        backup_frequency = self.charm_config.get('backup_frequency')
        if backup_frequency in ['hourly', 'daily', 'weekly', 'monthly']:
            backup_frequency = '@{}'.format(backup_frequency)
        cron_ctx = dict(
            frequency=backup_frequency,
            unit_name=hookenv.local_unit(),
            charm_dir=hookenv.charm_dir()
        )
        templating.render('periodic_backup', BACKUP_CRON_FILE, cron_ctx)
        with open('/etc/cron.d/periodic_backup', 'a') as cron_file:
            cron_file.write('\n')

    @staticmethod
    def update_known_host_file(known_host_key):
        permissions = 'a+' if os.path.exists(ROOT_KNOWN_HOSTS_PATH) else 'w+'
        with open(ROOT_KNOWN_HOSTS_PATH, permissions) as known_host_file:
            contents = known_host_file.read()
            if known_host_key not in contents:
                print(known_host_key, file=known_host_file)

    def do_backup(self, **kwargs):
        """ Execute the backup call to duplicity as configured by the charm

        :param: kwargs
        :type: dictionary of values that may be used instead of config values
        """
        self._set_environment_vars()
        cmd = self.backup_cmd
        hookenv.log("Duplicity Command: {}".format(cmd).replace(self.charm_config.get('remote_password'), '*****'))
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)

    def cleanup(self):
        #TODO
        # duplicity cleanup <target_url>
        raise NotImplementedError()

    def verify(self):
        #TODO
        # duplicity verify <target_url> <source_dir>
        raise NotImplementedError()

    def collection_status(self):
        #TODO
        # duplicity collection-status <target_url>
        raise NotImplementedError()

    def list_current_files(self, **kwargs):
        """
        Function that runs duplicity list current files in the remote
        directory.
        :return:
        """
        raise NotImplementedError()
        # self._set_environment_vars()
        # cmd = self.list_files_cmd
        # try:
        #     subprocess.check_call(cmd)
        # except subprocess.CalledProcessError as e:
        #     pass

    def restore(self):
        #TODO
        # duplicity restore <source_url> <target_dir>
        raise NotImplementedError()

    def remove_older_than(self):
        #TODO
        # duplicity remove-older-than time [options] target_url
        raise NotImplementedError()

    def remove_all_but_n_full(self):
        #TODO
        # duplicity remove-all-but-n-full <count> <target_url>
        raise NotImplementedError()

    def remove_all_inc_of_but_n_full(self):
        #TODO
        # duplicity remove-all-inc-of-but-n-full <count> <target_url>
        raise NotImplementedError()
