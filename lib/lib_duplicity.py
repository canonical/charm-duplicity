import subprocess
import os

from charmhelpers.core import hookenv

class DuplicityHelper():
    def __init__(self):
        self.charm_config = hookenv.config()

    def _backup_url(self):
        """
        Helper function to assemble the backup url into a format accepted
        by duplicity, based off of the 'backend' and 'remote_backup_url'
        defined in the charm config. _backup_url will be appended with the
        charms unit name to avoid overwriting backups from other sources in a
        scaled up environment.
        """
        backend = self.charm_config.get("backend").lower()
        # start building the url
        url = "{}://".format(backend)

        if backend in ["rsync", "scp", "ssh"]:
            # These all require SSH Type Authentication and will attempt to use
            # the provided remote host credentials
            user = self.charm_config.get("remote_user")
            password = self.charm_config.get("remote_password")
            if user:
                if password:
                    url += "{}:{}@".format(user, password)
                else:
                    url += "{}@".format(user)
            url += self.charm_config.get("remote_backup_url")
        elif backend in ["ftp", "sftp"]:
            # FTP requires remote credentials to be set, IIRC...
            # TODO - impl. later
            raise NotImplementedError
        elif backend == "s3":
            # The url should already be well formed
            url = self.charm_config.get("remote_backup_url")
        elif backend == "local":
            #local file, ensure it looks like a proper local url ""
            url = self.charm_config.get("remote_backup_url")
            if not url.startswith("file://"):
                url = "file://{}".format(url)
        else:
            return None
        url += "/{}".format(hookenv.local_unit().replace("/", "-"))
        return url

    def do_backup(self, **kwargs):
        """ Execute the backup call to duplicity as configured by the charm

        :param: kwargs
        :type: dictionary of values that may be used instead of
        """
        # print(self.charm_config)
        # print(self.charm_config.get("backend"))
        # print(self._backup_url())

        # Set the Aws Credentials. It doesnt matter if they are used or not
        os.environ["AWS_SECRET_ACCESS_KEY"] = self.charm_config.get(
            "aws_secret_access_key")
        os.environ["AWS_ACCESS_KEY_ID"] = self.charm_config.get(
            "aws_access_key_id")

        # Create the duplicity backup command
        if self.charm_config.get("full_backup"):
            cmd = ["duplicity", "full"]
        else:
            cmd = ["duplicity", "incr"]

        # Add source and destination
        cmd.append(self.charm_config.get("aux_backup_directory"))
        cmd.append(self._backup_url())

        if self.charm_config.get("disable_encryption"):
            cmd.append("--no-encryption")
        else:
            # set $PASSWORD or otherwise use encryption_passphrase
            os.environ["PASSWORD"] = self.charm_config.get(
                "encryption_passphrase")

        hookenv.log("Duplicity Command: " + " ".join(cmd))
        subprocess.check_call(cmd)
        return

    def cleanup(self):
        #TODO
        # duplicity cleanup <target_url>
        pass

    def verify(self):
        #TODO
        # duplicity verify <target_url> <source_dir>
        pass

    def collection_status(self):
        #TODO
        # duplicity collection-status <target_url>
        pass

    def list_current_files(self):
        # Set the Aws Credentials. It doesnt matter if they are used or not
        os.environ["AWS_SECRET_ACCESS_KEY"] = self.charm_config.get(
            "aws_secret_access_key")
        os.environ["AWS_ACCESS_KEY_ID"] = self.charm_config.get(
            "aws_access_key_id")

        cmd = "duplicity", "list-current-files", self._backup_url()

        if self.charm_config.get("disable_encryption"):
            cmd.append("--no-encryption")
        else:
            # set $PASSWORD or otherwise use encryption_passphrase
            os.environ["PASSWORD"] = self.charm_config.get(
                "encryption_passphrase")

        subprocess.check_call(cmd)

    def restore(self):
        #TODO
        # duplicity restore <source_url> <target_dir>
        pass

    def remove_older_than(self):
        #TODO
        # duplicity remove-older-than time [options] target_url
        pass

    def remove_all_but_n_full(self):
        #TODO
        # duplicity remove-all-but-n-full <count> <target_url>
        pass

    def remove_all_inc_of_but_n_full(self):
        #TODO
        # duplicity remove-all-inc-of-but-n-full <count> <target_url>
        pass
