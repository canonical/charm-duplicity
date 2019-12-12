#!/usr/local/sbin/charm-env python3

import sys
import subprocess

sys.path.append('lib')

from charmhelpers.core import hookenv
from charms.reactive import set_flag, clear_flag

from lib import lib_duplicity


error_workload_status = 'Periodic backup failed. Check unit logs for information.'


def main():
    try:
        hookenv.log('Performing backup.')
        output = lib_duplicity.DuplicityHelper().do_backup()
        hookenv.log('Periodic backup complete with following output:\n{}'.format(output.decode('utf-8')))
    except subprocess.CalledProcessError as e:
        err_msg = 'Perioid backup failed. Command "{}" failed with return code "{}" and error output:\n{}'.format(
            e.cmd, e.returncode, e.output.decode('utf-8'))
        hookenv.log(err_msg, level=hookenv.ERROR)
        hookenv.status_set('error', error_workload_status)
        set_flag('duplicity.failed_periodic_backup')
    except Exception as e:
        hookenv.log('Periodic backup failed: {}'.format(str(e)), level=hookenv.ERROR)
        hookenv.status_set('error', error_workload_status)
        set_flag('duplicity.failed_periodic_backup')
    else:
        clear_flag('duplicity.failed_periodic_backup')


if __name__ == "__main__":
    status, _ = hookenv.status_get()
    if status != 'active':
        hookenv.log('Duplicity unit must be in ready state to execute do-backup command.', level=hookenv.WARNING)
        sys.exit()
    main()
