#!/usr/local/sbin/charm-env python3

import os
import sys
from subprocess import CalledProcessError

sys.path.append('lib')

from charmhelpers.core import hookenv
from charms.reactive import clear_flag

from lib.lib_duplicity import DuplicityHelper


helper = DuplicityHelper()


def do_backup(*args):
    # TODO: Implement checking to see if application is active.
    output = helper.do_backup(logger=hookenv.log)
    hookenv.function_set(dict(output=output.decode('utf-8')))


ACTIONS = {
    'do-backup': do_backup
}


def main(args):
    action_name = os.path.basename(args[0])
    action = ACTIONS.get(action_name)
    if not action_name:
        return 'Action "{}" is undefined'.format(action_name)
    try:
        action(args)
    except CalledProcessError as e:
        err_msg = 'Command "{}" failed with return code "{}" and error output:\n{}'.format(
            e.cmd, e.returncode, e.output.decode('utf-8'))
        hookenv.log(err_msg, level=hookenv.ERROR)
        hookenv.function_fail(err_msg)
    except Exception as e:
        hookenv.function_fail(str(e))
    else:
        clear_flag('duplicity.failed_periodic_backup')


if __name__ == '__main__':
    sys.exit(main(sys.argv))