import subprocess

from charmhelpers.core import hookenv

class DuplicityHelper():
    def __init__(self):
        self.charm_config = hookenv.config()

    def show_history(self):
        """ Show the backup history by date and filesize """
        #TODO
        return

    def do_backup(self):
        """ Execute the backup script as configured by the charm """
        print(self.charm_config)
        print(self.charm_config.get("backend"))

        cmd = ["duplicity", "--version"]
        # FIXME - To implement...
        subprocess.check_call(cmd)
        return

    def _backup_url(self):
        """
        Helper function to assemble the backup url into a format accepted
        by duplicity, based off of the 'backend' and 'remote_backup_url'
        defined in the charm config
        """
        backend = self.charm_config.get("backend").lower()
        if backend in ["rsync", "scp", "ssh"]:
            # These all require SSH Type Authentication and will attempt to use
            # the provided remote host credentials
            user = self.charm_config.get("remote_user")
            password = self.charm.config.get("remote_password")

            # start building the url
            url = "{}://".format(backend)
            if user:
                if password:
                    url +=  "{}:{}@".format(user, password)
                else:
                    url += "{}@".format(user)
            url += self.charm_config.get("remote_backup_url")
            return url
            # TODO - UNIT TESTS!
            # rsync://user[:password]@other.host[:port]::/module/some_dir
            # rsync://user[:password]@other.host[:port]/relative_path
            # rsync://user[:password]@other.host[:port]//absolute_path
            # scp://user[:password]@other.host[:port]/some_dir
            # ssh://user[:password]@other.host[:port]/some_dir
        elif backend in ["ftp", "ftps"]:
            # FTP requires remote credentials to be set, IIRC...
            # TODO - impl. later
            raise NotImplementedError
        elif backend == "s3":
            # This will require AWS IMA user keys, TODO: check for those later
            # The url should already be well formed
            return self.charm_config.get("remote_backup_url")
        elif backend == "local":
            #local file, ensure it looks like a proper local url ""
            url = self.charm_config.get("remote_backup_url")
            if url.startswith("file://"):
                return url
            else:
                return "file://{}".format(url)
        elif backend != "":
            # invalid backend set - we should log a warning then not do the
            # requested action later
            # TODO - figure out logging
            # does this belong in /var/log/juju/unit-duplicity?
            # or /var/log/duplicity
            pass

        return None


