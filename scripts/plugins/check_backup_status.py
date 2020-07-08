#!/usr/bin/env python3

"""NRPE checks."""

import os
import sys

error_file = '/var/run/periodic_backup.error'


def main():
    """If error_file exists, backup is not successful."""
    if os.path.exists(error_file):
        with open(error_file) as f:
            print('WARNING: Backup not completed successfully:\n', f.read())
        return 1
    print('OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
