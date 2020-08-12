#!/usr/local/sbin/charm-env python3
"""Supported actions for juju run-action."""

import os
import sys
import traceback
from subprocess import CalledProcessError

sys.path.append('lib')

from charmhelpers.core import hookenv

from charms.reactive import clear_flag

from lib_duplicity import DuplicityHelper


helper = DuplicityHelper()
error_file = '/var/run/periodic_backup.error'


def do_backup(*args):
    """do-backup action."""
    output = helper.do_backup()
    hookenv.function_set(dict(output=output.decode('utf-8')))


ACTIONS = {
    'do-backup': do_backup
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
        err_msg = 'Command "{}" failed with return code "{}" and error output:\n{}'.format(
            e.cmd, e.returncode, e.output.decode('utf-8'))
        hookenv.log(err_msg, level=hookenv.ERROR)
        hookenv.function_fail(err_msg)
    except Exception as e:
        hookenv.log('do-backup action failed: {}\n{}'.format(e, traceback.print_exc()), level=hookenv.ERROR)
        hookenv.function_fail(str(e))
    else:
        clear_flag('duplicity.failed_backup')
        if os.path.exists(error_file):
            os.remove(error_file)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
