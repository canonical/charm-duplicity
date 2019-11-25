import os
import sys
import time

dir_path = os.path.dirname(os.path.realpath(__file__))
hooks_path = os.path.abspath(os.path.join(dir_path, "..", "hooks"))
root_path = os.path.abspath(os.path.join(dir_path, ".."))

for p in [hooks_path, root_path]:
    if p not in sys.path:
        sys.path.append(p)

# now we can import charm related items
import charmhelpers.core.hookenv
from lib import lib_duplicity


def cli_log(msg, level=charmhelpers.core.hookenv.INFO):
    """Helper function to write log message to stdout/stderr for CLI usage."""
    if level == charmhelpers.core.hookenv.DEBUG:
        return charmhelpers.core.hookenv.log(msg, level=level)
    elif level in [charmhelpers.core.hookenv.ERROR,
                   charmhelpers.core.hookenv.WARNING]:
        output = sys.stderr
    else:
        output = sys.stdout

    print('{}: {}'.format(time.ctime(), msg), file=output)


# the rotate_and_sync_keys() function checks for leadership AND whether to
# rotate the keys or not.
if __name__ == "__main__":
    helper = lib_duplicity.DuplicityHelper().do_backup()
