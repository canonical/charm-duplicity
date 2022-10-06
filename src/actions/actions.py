#!/usr/local/sbin/charm-env python3
"""Supported actions for juju run-action."""

import os
import sys
import traceback
from subprocess import CalledProcessError

sys.path.append("lib")

from charmhelpers.core import hookenv

from charms.reactive import clear_flag

from lib_duplicity import DuplicityHelper


helper = DuplicityHelper()
error_file = "/var/run/periodic_backup.error"


def do_backup(*args):
    """do-backup action."""
    output = helper.do_backup()
    hookenv.function_set(dict(output=output.decode("utf-8")))


def list_current_files(*args):
    """list-current-files action."""
    output = helper.list_current_files()
    hookenv.function_set(dict(output=output.decode("utf-8")))


def remove_older_than(*args):
    """remove-older-than action."""
    time = hookenv.action_get("time")
    output = helper.remove_older_than(time=time)
    hookenv.function_set(dict(output=output.decode("utf-8")))


def remove_all_but_n_full(*args):
    """remove-all-but-n-full action."""
    count = hookenv.action_get("count")
    output = helper.remove_all_but_n_full(count=count)
    hookenv.function_set(dict(output=output.decode("utf-8")))


def remove_all_inc_of_but_n_full(*args):
    """remove-all-inc-of-but-n-full action."""
    count = hookenv.action_get("count")
    output = helper.remove_all_inc_of_but_n_full(count=count)
    hookenv.function_set(dict(output=output.decode("utf-8")))


ACTIONS = {
    "do-backup": do_backup,
    "list-current-files": list_current_files,
    "remove-older-than": remove_older_than,
    "remove-all-but-n-full": remove_all_but_n_full,
    "remove-all-inc-of-but-n-full": remove_all_inc_of_but_n_full,
}


def main(args):
    """Supported actions."""
    action_name = os.path.basename(args[0])
    action = ACTIONS.get(action_name)
    if not action:
        return 'Action "{}" is undefined'.format(action_name)
    try:
        action(args)
    except CalledProcessError as e:
        err_msg = (
            'Command "{}" failed with return code "{}" '
            "and error output:\n{}".format(
                e.cmd, e.returncode, e.output.decode("utf-8")
            )
        )
        hookenv.log(err_msg, level=hookenv.ERROR)
        hookenv.function_fail(err_msg)
    except Exception as e:
        hookenv.log(
            "{} action failed: {}\n{}".format(action_name, e, traceback.print_exc()),
            level=hookenv.ERROR,
        )
        hookenv.function_fail(str(e))
    else:
        if action_name == "do-backup":
            clear_flag("duplicity.failed_backup")
        if os.path.exists(error_file):
            os.remove(error_file)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
