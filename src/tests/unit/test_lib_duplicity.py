#!/usr/bin/python3
"""Duplicity helper unit tests."""
from unittest.mock import ANY, call, mock_open, patch

import lib_duplicity

import pytest


class TestDuplicityHelper:
    """This class defines duplicity helper unit tests."""

    @pytest.mark.parametrize(
        "backend,remote_backup_url,expected_destination",
        [
            ("scp", "some.host/backups", "scp://some.host/backups/unit-mock-0"),
            ("rsync", "some.host/backups", "rsync://some.host/backups/unit-mock-0"),
            ("ftp", "some.host/backups", "ftp://some.host/backups/unit-mock-0"),
            ("sftp", "some.host/backups", "sftp://some.host/backups/unit-mock-0"),
            ("s3", "some.host/backups", "s3://some.host/backups/unit-mock-0"),
            ("file", "some.host/backups", "file://some.host/backups/unit-mock-0"),
            ("else", "host", None),
        ],
    )
    def test_backup_cmd(
        self, duplicity_helper, backend, remote_backup_url, expected_destination
    ):
        """Verify backup command."""
        duplicity_helper.charm_config["backend"] = backend
        duplicity_helper.charm_config["remote_backup_url"] = remote_backup_url
        command = duplicity_helper.backup_cmd
        assert "duplicity" in command
        assert "/tmp/duplicity" in command
        assert expected_destination in command

    @pytest.mark.parametrize(
        "backend,remote_backup_url,expected_destination",
        [
            ("scp", "some.host/backups", "scp://some.host/backups/unit-mock-0"),
            ("rsync", "some.host/backups", "rsync://some.host/backups/unit-mock-0"),
            ("ftp", "some.host/backups", "ftp://some.host/backups/unit-mock-0"),
            ("sftp", "some.host/backups", "sftp://some.host/backups/unit-mock-0"),
            ("s3", "some.host/backups", "s3://some.host/backups/unit-mock-0"),
            ("file", "some.host/backups", "file://some.host/backups/unit-mock-0"),
            ("else", "host", None),
        ],
    )
    def test_list_current_files_cmd(
        self, duplicity_helper, backend, remote_backup_url, expected_destination
    ):
        """Verify list-current-files command."""
        duplicity_helper.charm_config["backend"] = backend
        duplicity_helper.charm_config["remote_backup_url"] = remote_backup_url
        command = duplicity_helper.backup_cmd
        assert expected_destination in command
        command = duplicity_helper.list_files_cmd
        assert "duplicity" in command
        assert expected_destination in command

    @pytest.mark.parametrize(
        "user,password,expected_destination",
        [
            ("ubuntu", None, "scp://ubuntu@some.host/backups/unit-mock-0"),
            (
                "ubuntu",
                "somepass",
                "scp://ubuntu:somepass@some.host/backups/unit-mock-0",
            ),
        ],
    )
    def test_backup_cmd_user_password(
        self, duplicity_helper, user, password, expected_destination
    ):
        """Verify backup command with user and password."""
        backend = "scp"
        remote_backup_url = "some.host/backups"
        duplicity_helper.charm_config["backend"] = backend
        duplicity_helper.charm_config["remote_backup_url"] = remote_backup_url
        duplicity_helper.charm_config["remote_user"] = user
        duplicity_helper.charm_config["remote_password"] = password
        command = duplicity_helper.backup_cmd
        assert expected_destination in command

    @pytest.mark.parametrize(
        "disable_encryption,gpg_public_key,private_ssh_key,expected_options",
        [
            (True, None, None, ["--no-encryption"]),
            (None, "GPGK3Y", None, ["--encrypt-key=GPGK3Y"]),
            (
                None,
                None,
                "mykey",
                ["--ssh-options=-oIdentityFile=/root/.ssh/duplicity_id_rsa"],
            ),
            (
                True,
                "GPGK3Y",
                "mykey",
                [
                    "--no-encryption",
                    "--ssh-options=-oIdentityFile=/root/.ssh/duplicity_id_rsa",
                ],
            ),
            (
                None,
                "GPGK3Y",
                "mykey",
                [
                    "--encrypt-key=GPGK3Y",
                    "--ssh-options=-oIdentityFile=/root/.ssh/duplicity_id_rsa",
                ],
            ),
        ],
    )
    def test_backup_cmd_additional_options(
        self,
        duplicity_helper,
        disable_encryption,
        gpg_public_key,
        private_ssh_key,
        expected_options,
    ):
        """Verify additional options of backup command."""
        duplicity_helper.charm_config["disable_encryption"] = disable_encryption
        duplicity_helper.charm_config["gpg_public_key"] = gpg_public_key
        duplicity_helper.charm_config["private_ssh_key"] = private_ssh_key
        command = duplicity_helper.backup_cmd
        for expected_option in expected_options:
            assert expected_option in command

    @pytest.mark.parametrize(
        "aws_secret_access_key,aws_access_key_id,encryption_passphrase",
        [("key", "key_id", "mypass"), ("key", "key_id", ""), ("", "", "")],
    )
    @patch("lib_duplicity.subprocess")
    @patch("lib_duplicity.os")
    def test_do_backup(
        self,
        mock_os,
        mock_subprocess,
        duplicity_helper,
        aws_secret_access_key,
        aws_access_key_id,
        encryption_passphrase,
    ):
        """Verify do backup action."""
        duplicity_helper.charm_config["aws_secret_access_key"] = aws_secret_access_key
        duplicity_helper.charm_config["aws_access_key_id"] = aws_access_key_id
        duplicity_helper.charm_config["encryption_passphrase"] = encryption_passphrase
        duplicity_helper.do_backup()
        mock_subprocess.check_output.assert_called_once()
        calls = [
            call("PASSWORD", encryption_passphrase),
            call("AWS_SECRET_ACCESS_KEY", aws_secret_access_key),
            call("AWS_ACCESS_KEY_ID", aws_access_key_id),
        ]
        mock_os.environ.__setitem__.assert_has_calls(calls, any_order=True)

    @pytest.mark.parametrize(
        "backup_frequency,expected_frequency",
        [
            ("hourly", "@hourly"),
            ("daily", "@daily"),
            ("weekly", "@weekly"),
            ("monthly", "@monthly"),
            ("* * * * *", "* * * * *"),
        ],
    )
    @patch("lib_duplicity.os")
    @patch("lib_duplicity.templating")
    @patch("builtins.open")
    def test_setup_backup_cron(
        self,
        mock_open,
        mock_templating,
        mock_os,
        duplicity_helper,
        backup_frequency,
        expected_frequency,
    ):
        """Verify setup backup cron job."""
        duplicity_helper.charm_config["backup_frequency"] = backup_frequency
        duplicity_helper.setup_backup_cron()
        args, _ = mock_templating.render.call_args
        actual_frequency = args[2]["frequency"]
        assert actual_frequency == expected_frequency

    @pytest.mark.parametrize("exists", [True, False])
    @patch("lib_duplicity.os")
    @patch("lib_duplicity.templating")
    @patch("builtins.open")
    def test_setup_backup_cron_create_path(
        self, mock_open, mock_templating, mock_os, duplicity_helper, exists
    ):
        """Verify setup_backup_cron create dir."""
        mock_os.path.exists.return_value = exists
        duplicity_helper.setup_backup_cron()
        assert mock_os.mkdir.called is not exists

    @pytest.mark.parametrize(
        "key_exists,path_exists,permission,written",
        [
            (True, True, "a+", False),
            (True, False, "w+", False),
            (False, True, "a+", True),
            (False, False, "w+", True),
        ],
    )
    @patch("lib_duplicity.os")
    @patch("builtins.print")
    def test_update_known_host_file(
        self, mock_print, mock_os, key_exists, path_exists, permission, written
    ):
        """Verify updating knwon host file."""
        known_host_key = "known_host_key"
        read_data = known_host_key if key_exists else "other"
        mock_os.path.exists.return_value = path_exists
        with patch("lib_duplicity.open", mock_open(read_data=read_data)) as m_open:
            lib_duplicity.DuplicityHelper.update_known_host_file(known_host_key)
        m_open.assert_called_with(ANY, permission)
        assert mock_print.called == written


class TestLibDuplicity:
    """Test functions defined in lib_duplicity."""

    @patch("lib_duplicity.os")
    def test_safe_remove_backup_cron_path_exists(self, mock_os):
        """Verify removing backup cron path if exists."""
        mock_os.path.exists.return_value = True
        lib_duplicity.safe_remove_backup_cron()
        mock_os.remove.assert_called_once()

    @patch("lib_duplicity.os")
    def test_safe_remove_backup_cron_no_exist(self, mock_os):
        """Verify removing backup cron path if it doesn't exist."""
        mock_os.path.exists.return_value = False
        lib_duplicity.safe_remove_backup_cron()
        mock_os.remove.assert_not_called()
