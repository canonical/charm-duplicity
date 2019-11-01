from charmhelpers.core import hookenv

class DuplicityHelper():
    def __init__(self):
        self.charm_config = hookenv.config()

    def show_history(self):
        """ Show the backup history by date and filesize"""
        #TODO
        return

