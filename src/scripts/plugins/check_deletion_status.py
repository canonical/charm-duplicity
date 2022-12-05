#!/usr/bin/env python3

"""NRPE checks."""

import os
import sys

error_file = "/var/run/periodic_deletion.error"


def main():
    """If error_file exists, deletion is not successful."""
    if os.path.exists(error_file):
        with open(error_file) as f:
            print("WARNING: Deletion not completed successfully:\n", f.read())
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
