#!/usr/bin/env python3

import sys
import os

error_file = '/var/run/periodic_backup.error'


def main():
    if os.path.exists(error_file):
        with open(error_file) as f:
            print('WARNING: Backup not completed successfully:\n', f.read())
        return 1
    print('OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
