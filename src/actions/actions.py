#!/usr/local/sbin/charm-env python3
"""Supported actions for juju run-action."""

import os
import sys
import traceback
from subprocess import CalledProcessError

sys.path.append("lib")

from charmhelpers.core import hookenv  # noqa: E402

from charms.reactive import clear_flag  # noqa: E402

from lib_duplicity import DuplicityHelper  # noqa: E402


helper = DuplicityHelper()
error_file = "/var/run/periodic_backup.error"


def do_backup(*_):
    """do-backup action."""
    output = helper.do_backup()
    hookenv.action_set({"output": output.decode("utf-8")})


def list_current_files(*_):
    """list-current-files action."""
    output = helper.list_current_files()
    hookenv.action_set({"output": output.decode("utf-8")})


def remove_older_than(*_):
    """remove-older-than action."""
    output = helper.remove_older_than(hookenv.action_get("time"))
    hookenv.action_set({"output": output.decode("utf-8")})


def remove_all_but_n_full(*_):
    """remove-all-but-n-full action."""
    output = helper.remove_all_but_n_full(hookenv.action_get("count"))
    hookenv.action_set({"output": output.decode("utf-8")})


def remove_all_inc_of_but_n_full(*_):
    """remove-all-inc-of-but-n-full action."""
    output = helper.remove_all_inc_of_but_n_full(hookenv.action_get("count"))
    hookenv.action_set({"output": output.decode("utf-8")})


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
        err_msg = 'Command "{}" failed with return code "{}" ' "and error output:{}{}".format(
            e.cmd, e.returncode, os.linesep, e.output.decode("utf-8")
        )
        hookenv.log(err_msg, level=hookenv.ERROR)
        hookenv.action_fail(err_msg)
    except Exception as e:
        hookenv.log(
            "{} action failed: {}{}{}".format(action_name, e, os.linesep, traceback.print_exc()),
            level=hookenv.ERROR,
        )
        hookenv.action_fail(str(e))
    else:
        if action_name == "do-backup":
            clear_flag("duplicity.failed_backup")
        if os.path.exists(error_file):
            os.remove(error_file)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
