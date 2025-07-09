> [!NOTE]
> This charm is under maintenance mode. Only critical bug will be handled.

# Duplicity Charm

## Overview

The Duplicity charm provides functionality for both manual and automatic backups for a deployed application.
As the name suggests, it utilizes the Duplicity tool and acts as an easy-to-use-and-configure interface for
operators to set up backups.

After relating the [Duplicity](http://duplicity.nongnu.org/) charm to another charm, you can backup a directory to
either the local unit, a remote host, or even an AWS S3 bucket. All it takes is a bit of configuration and
remote destination preparation.

The following backends are currently supported:
- File (local)
- S3
- SCP
- Rsync
- FTP/SFTP

# Usage

### Simple deployment

This will get duplicity deployed on whatever deployed charm you want. Here, we see
it being related to the ubuntu charm.

```bash
juju deploy ubuntu
juju deploy duplicity
juju add-relation duplicity ubuntu
```

However, we will need to fill out various other, required configs, depending on the backend type selected.

### Local file backups

This will backup a selected directory to the local unit.

```
juju config duplicity \
    backend=file \
    remote_backup_url=file:///home/me/backups
    aux_backup_dir=/path/to/back/up
```

### SCP/Rsync/SFTP Backups

Using the backends scp, rsync, and sftp require, at minimum, the following options to be set.

```
juju config duplicity \
    backend=scp \
    remote_backup_url=my.host:22/my_backups
    known_host_key='my.host,10.10.10.2 ssh-rsa AAABBBCCC' \
    private_ssh_key="$(base64 my_priv_id)"
```

Alternatively, you can use `remote_password=password` instead of the `private_ssh_key` option if you prefer
password authentication.

### S3 Backups

The following will backup to S3 buckets. This configuration requires an IAM account
access and secret key to be passed into the config.

```
juju config duplicity \
    backend=s3 \
    remote_backup_url=s3:my.aws.com/bucket_name/prefix \
    aws_access_key_id=my_aws_key \
    aws_secret_access_key=my_aws_secret
```

### Encryption

To encrypt your backups, you can use symmetric encryption using a passed in password or
encrypt the backup with a GPG key. Alternative to these methods, you can ignore encryption
entirely.

```
# Symmetric password encryption
juju config duplicity encryption_passphrase=my_passphrase

# Asymmetric GPG encryption
juju config duplicity gpg_public_key=MY_GPG_KEY

# Disable encryption (not recommended)
juju config duplicity disable_encryption=True
```

### Setting Periodic Backups

The big draw of this charm is being able to periodically backup a directory. By default,
the charm will only backup manually, i.e. through the `do-backup` action. To enable
periodic backups, set `backup_frequency` to any of the following:

- hourly
- daily
- weekly
- monthly
- any valid cron schedule string

### Setting Retention

The charm supports periodically cleaning up stale backups. A retention period can
be set with `retention_period` and the charm will periodically delete backups older
than this time period. By default, the charm's retention policy is set to manual
and can be set as follows:
- manual (*default*)
- <n>h (number of hour(s) eg. 3h, 60h, 10000h)
- <n>d (number of day(s) eg. 1d, 7d, 30d, 100000d)

How frequently old backups are deleted can be set with `deletion_frequency`
which by default is set to daily.
- daily (runs at 23:00) (*default*)
- hourly (runs at the 40th minute)
- any valid cron schedule string

### Adding NRPE Checks for alerting

Adding NRPE checks allows for alerting when a periodic backup or deletion fails to complete.

```bash
juju deploy nrpe
juju add-relation nrpe ubuntu       # required on host
juju add-relation nrpe duplicity
```

### Cleaning up backups

Deletion commands such as `remove-older-than`, `remove-all-but-n-full` and
`remove-all-inc-of-but-n-full` can be used with run action and a specified
parameter.
For example:
    `juju run-action duplicity/0 remove-older-than time=2022-10-02T19:44:00+00:00`
        where time follows the same w3 standard as duplicity and yaml
    `juju run-action duplicity/0 remove-all-but-n-full count=1`

# Known Limitations and Future Features

This charm is currently still under development. The only supported Duplicity actions right now is full backups (through both an action and periodic backups) and removal of backups.
The following is the list of future Duplicity functionality:

- incremental backups
- restoring backups
- verifying backups
- listing backed-up files
- additional supported backends

# Upstream and Bugs

The repository can be found [here](https://git.launchpad.net/charm-duplicity).

Please report bugs or feature requests on [Launchpad](https://bugs.launchpad.net/charm-duplicity).
