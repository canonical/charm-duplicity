import subprocess

from charmhelpers.core import hookenv

class DuplicityHelper():
    def __init__(self):
        self.charm_config = hookenv.config()

    def _backup_url(self):
        """
        Helper function to assemble the backup url into a format accepted
        by duplicity, based off of the 'backend' and 'remote_backup_url'
        defined in the charm config
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

            return url

        elif backend in ["ftp", "ftps"]:
            # FTP requires remote credentials to be set, IIRC...
            # TODO - impl. later
            raise NotImplementedError
        elif backend == "s3":
            # The url should already be well formed
            return url + self.charm_config.get("remote_backup_url")
        elif backend == "local":
            #local file, ensure it looks like a proper local url ""
            url = self.charm_config.get("remote_backup_url")
            if url.startswith("file://"):
                return url
            else:
                return "file://{}".format(url)

        return None

    def do_backup(self):
        """ Execute the backup script as configured by the charm """
        print(self.charm_config)
        print(self.charm_config.get("backend"))
        print(self._backup_url())

        cmd = ["duplicity", "--version"]
        # FIXME - To implement...
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
        #TODO
        # duplicity list-current-files <target_url>
        pass

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
