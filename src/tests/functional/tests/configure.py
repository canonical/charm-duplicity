"""Set up functional tests."""

import logging
import subprocess

import zaza.model


ubuntu_user_pass = "ubuntu:sUp3r5ecr3tP45SW0rd"
ubuntu_backup_directory_source = "/home/ubuntu/test-files"


def set_ubuntu_password_on_backup_host():
    """Set ubuntu password on backup host."""
    command = 'echo "{}" | chpasswd'.format(ubuntu_user_pass)
    backup_host_unit = _get_unit("backup-host")
    result = zaza.model.run_on_unit(backup_host_unit.name, command, timeout=15)
    _check_run_result(result)


def set_ssh_password_access_on_backup_host():
    """Configure ssh access with password on backup host."""
    backup_host_unit = _get_unit("backup-host")
    command = (
        'echo "PasswordAuthentication yes" > 01-test-settings.conf &&'
        "service sshd reload"
    )
    result = zaza.model.run_on_unit(backup_host_unit.name, command, timeout=15)
    _check_run_result(result)


def setup_test_files_for_backup():
    """Create test files for backup."""
    ubuntu_unit = _get_unit("ubuntu")
    command = 'runuser -l ubuntu -c "mkdir {}"'.format(ubuntu_backup_directory_source)
    result = zaza.model.run_on_unit(ubuntu_unit.name, command, timeout=15)
    _check_run_result(result, codes=["1"])
    zaza.model.scp_to_unit(
        unit_name=ubuntu_unit.name,
        source="./tests/resources/hello-world.txt",
        destination=ubuntu_backup_directory_source,
    )


def set_backup_host_known_host_key():
    """Configure known host key for backup host."""
    backup_host_ip = _get_unit("backup-host").public_address
    command = ["ssh-keyscan", "-t", "rsa", backup_host_ip]
    output = subprocess.check_output(command)
    zaza.model.set_application_config(
        "duplicity", dict(known_host_key=output.decode("utf-8").strip())
    )


def add_pub_key_to_backup_host():
    """Set up ssh access with private key on backup host."""
    backup_host_unit = _get_unit("backup-host")
    with open("./tests/resources/testing_id_rsa.pub") as f:
        pub_key = f.read().strip()
    command = 'echo "{}" >> /home/ubuntu/.ssh/authorized_keys'.format(pub_key)
    result = zaza.model.run_on_unit(backup_host_unit.name, command, timeout=15)
    _check_run_result(result)


def setup_ftp():
    """Configure ftp server."""
    backup_host_unit = _get_unit("backup-host")
    install_command = "apt install -y vsftpd"
    result = zaza.model.run_on_unit(backup_host_unit.name, install_command, timeout=15)
    _check_run_result(result)
    vsconf = [
        "write_enable",
        "ascii_upload_enable",
        "ascii_download_enable",
        "chroot_local_user",
        "chroot_list_enable",
        "ls_recurse_enable",
    ]
    configure_command = (
        'for i in {}; do sed -i "s/#$i/$i/" /etc/vsftpd.conf; done && '
        "echo ubuntu > /etc/vsftpd.chroot_list && "
        "systemctl restart vsftpd".format(" ".join(vsconf))
    )
    result = zaza.model.run_on_unit(
        backup_host_unit.name, configure_command, timeout=15
    )
    _check_run_result(result)


def _check_run_result(result, codes=None):
    """Verify code contained in result."""
    if not result:
        raise Exception("Failed to get a result from run_on_unit command.")
    allowed_codes = list("0")
    if codes:
        allowed_codes.extend(codes)
    if result["Code"] not in allowed_codes:
        logging.error(
            "Bad result code received. Result code: {}".format(result["Code"])
        )
        logging.error("Returned: \n{}".format(result))
        raise Exception("Command returned non-zero return code.")


def _get_unit(app):
    """Return an unit of the given app."""
    return zaza.model.get_units(app)[0]
