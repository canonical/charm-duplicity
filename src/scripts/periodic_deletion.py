#!/usr/local/sbin/charm-env python3

"""Periodic deletion."""

import os
import subprocess
import sys

sys.path.append("lib")

from charmhelpers.core import hookenv  # noqa: E402
from charms.reactive import clear_flag  # noqa: E402
from pidfile import PidFile  # noqa: E402

from lib import lib_duplicity  # noqa: E402

pidfile = "/var/run/periodic_deletion.pid"
error_file = "/var/run/periodic_deletion.error"


def write_error_file(message):
    """Write error log if backup failed."""
    with open(error_file, "w") as f:
        f.write(message)


def main():
    """Periodically backup with juju run-action do-backup."""
    try:
        hookenv.log("Performing deletion.")
        output = lib_duplicity.DuplicityHelper().do_deletion()
        hookenv.log(
            "Periodic deletion complete with following output:\n{}".format(output.decode("utf-8"))
        )
    except subprocess.CalledProcessError as e:
        err_msg = (
            'Periodic deletion failed. Command "{}" failed with return code "{}" '
            "and error output:\n{}".format(e.cmd, e.returncode, e.output.decode("utf-8"))
        )

        hookenv.log(err_msg, level=hookenv.ERROR)
        write_error_file(err_msg)
    except Exception as e:
        err_msg = "Periodic deletion failed: {}".format(str(e))
        hookenv.log(err_msg, level=hookenv.ERROR)
        write_error_file(err_msg)
    else:
        clear_flag("duplicity.failed_deletion")
        if os.path.exists(error_file):
            os.remove(error_file)


if __name__ == "__main__":
    status, workload_msg = hookenv.status_get()
    if status != "active":
        hookenv.log(
            "Duplicity unit must be in ready state to execute\
                periodic deletion command.",
            level=hookenv.WARNING,
        )
        sys.exit()
    with PidFile(pidfile):
        main()
