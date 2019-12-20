# Overview

The Duplicity charm provides functionality for both manual and automatic backups for a deployed application.
As the name suggests, it utilizes the Duplicity tool and acts as an easy-to-use-and-configure interface for 
operators to set up backups.

After relating the [Duplicity](http://duplicity.nongnu.org/) to another charm, you can backup a directory to 
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

However, we will need to fill out 

### Local file backups
```
juju config duplicity \
    backend=file \
    remote_backup_url=file:///home/me/backups
    aux_backup_dir=/path/to/back/up
```

### SCP/Rsync/SFTP Backups

```
juju config duplicity \
    backend=scp \
    remote_backup_url=my.host:22/my_backups
    known_host_key='my.host,10.10.10.2 ssh-rsa AAABBBCCC' \
    private_ssh_key=$(base64 my_priv_id)
```

Alternatively, you can use `remote_password=password` instead of the `private_ssh_key` option if you prefer
password authentication.

### S3 Backups
```
juju config duplicity \
    backend=s3 \
    remote_backup_url=s3:my.aws.com/bucket_name/prefix \
    aws_access_key_id=my_aws_key \
    aws_secret_access_key=my_aws_secret
```

### Adding NRPE Checks for alerting
```bash
juju deploy nrpe
juju add-relation nrpe ubuntu       # required on host 
juju add-relation nrpe duplicity
```

# Bugs

Please report bugs or feature requests on [Launchpad](https://bugs.launchpad.net/charm-duplicity).
