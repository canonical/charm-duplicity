"""Unit tests for reactive hooks."""

from unittest import TestCase
from unittest.mock import ANY, MagicMock, call, mock_open, patch

from croniter import CroniterBadCronError, CroniterBadDateError, CroniterNotAlphaError

import pytest

with patch("lib_duplicity.DuplicityHelper") as helper_mock:
    with patch("charmhelpers.core.hookenv") as hookenv_mock:
        import duplicity


class TestInstallDuplicity(TestCase):
    """Verify charm installation."""

    @patch("duplicity.hookenv")
    @patch("duplicity.fetch")
    @patch("duplicity.set_flag")
    def test_install_duplicity(self, mock_set_flag, mock_fetch, mock_hookenv):
        """Verify install hook."""
        hookenv_calls = [
            call("maintenance", "Installing duplicity"),
            call("active", ""),
        ]
        fetch_calls = [
            call(x) for x in ["duplicity", "python-paramiko", "python-boto", "lftp"]
        ]
        duplicity.install_duplicity()
        mock_hookenv.status_set.assert_has_calls(hookenv_calls)
        mock_fetch.apt_install.assert_has_calls(fetch_calls)
        mock_set_flag.assert_called_with("duplicity.installed")

    @patch("subprocess.run")
    def test_install_duplicity_raises_when_pip_fails(self, mock_subprocess_run):
        """Verify that charm installation fails when pip fails."""
        mock_subprocess_run.return_value = MagicMock(
            returncode=1, stderr=b"failed to install package with pip"
        )
        with self.assertRaises(duplicity.PipPackageInstallError):
            duplicity.install_duplicity()

    @patch("duplicity.hookenv")
    @patch("duplicity.fetch")
    @patch("duplicity.set_flag")
    @patch("subprocess.run")
    def test_install_duplicity_succeeds_when_pip_suceeds(
        self, mock_subprocess_run, mock_set_flag, mock_fetch, mock_hookenv
    ):
        """Verify that charm installation fails when pip fails."""
        hookenv_calls = [
            call("maintenance", "Installing duplicity"),
            call("active", ""),
        ]
        fetch_calls = [
            call(x) for x in ["duplicity", "python-paramiko", "python-boto", "lftp"]
        ]
        mock_subprocess_run.return_value = MagicMock(
            returncode=0, stdout=b"package installed!"
        )
        duplicity.install_duplicity()
        mock_hookenv.status_set.assert_has_calls(hookenv_calls)
        mock_fetch.apt_install.assert_has_calls(fetch_calls)
        mock_set_flag.assert_called_with("duplicity.installed")


class TestValidateBackend:
    """Verify validation of duplicity backend."""

    @pytest.mark.parametrize("backend,", ["ftp", "file"])
    @patch("duplicity.set_flag")
    @patch("duplicity.clear_flag")
    @patch("duplicity.config")
    def test_validate_backend_success_not_secured(
        self, mock_config, mock_clear_flag, mock_set_flag, backend
    ):
        """Verify valid not secured backend."""
        mock_config.get.return_value = backend
        duplicity.validate_backend()
        mock_clear_flag.assert_called_with("duplicity.invalid_backend")
        mock_set_flag.assert_not_called()

    @pytest.mark.parametrize(
        "backend,remote_password,ssh_key",
        [
            ("scp", "remote-pass", None),
            ("scp", None, "ssh_key"),
            ("rsync", None, "ssh_key"),
            ("sftp", "remote-pass", None),
            ("sftp", None, "ssh_key"),
        ],
    )
    @patch("duplicity.set_flag")
    @patch("duplicity.clear_flag")
    @patch("duplicity.config")
    def test_validate_backend_success_secured(
        self,
        mock_config,
        mock_clear_flag,
        mock_set_flag,
        backend,
        remote_password,
        ssh_key,
    ):
        """Verify valid secured backend."""
        known_host_key = "host_key"
        if backend == "rsync":
            side_effects = [backend, ssh_key, known_host_key, remote_password, ssh_key]
        else:
            side_effects = [backend, known_host_key, remote_password, ssh_key]
        mock_config.get.side_effect = side_effects
        duplicity.validate_backend()
        mock_set_flag.assert_not_called()
        mock_clear_flag.assert_called_with("duplicity.invalid_secure_backend_opts")

    @patch("duplicity.set_flag")
    @patch("duplicity.clear_flag")
    @patch("duplicity.config")
    def test_invalid_backend_secured_no_private_ssh_key_rsync(
        self, mock_config, mock_clear_flag, mock_set_flag
    ):
        """Verify invalid backend."""
        backend = "rsync"
        known_host_key = "host_key"
        remote_password = "remote-pass"
        mock_config.get.side_effect = [
            backend,
            None,
            known_host_key,
            remote_password,
            None,
        ]
        duplicity.validate_backend()
        mock_clear_flag.assert_called_with("duplicity.invalid_backend")
        mock_set_flag.assert_called_with("duplicity.invalid_rsync_key")

    @pytest.mark.parametrize("backend", ["scp", "rsync"])
    @patch("duplicity.set_flag")
    @patch("duplicity.clear_flag")
    @patch("duplicity.config")
    def test_invalid_backend_secured_no_host_key(
        self, mock_config, mock_clear_flag, mock_set_flag, backend
    ):
        """Verify invalid backend."""
        if backend == "rsync":
            mock_config.get.side_effect = [backend, "ssk_key", None, None, "ssh_key"]
        else:
            mock_config.get.side_effect = [backend, None, None, None]
        duplicity.validate_backend()
        mock_set_flag.assert_called_with("duplicity.invalid_secure_backend_opts")
        if backend == "rsync":
            mock_clear_flag.assert_called_with("duplicity.invalid_rsync_key")
        else:
            mock_clear_flag.assert_called_with("duplicity.invalid_backend")

    @patch("duplicity.set_flag")
    @patch("duplicity.clear_flag")
    @patch("duplicity.config")
    def test_validate_backend_success_s3(
        self, mock_config, mock_clear_flag, mock_set_flag
    ):
        """Verify valid s3 backend."""
        backend = "s3"
        mock_config.get.side_effect = [backend, "aws_id", "aws_secret"]
        expected_calls = [
            call("duplicity.invalid_backend"),
            call("duplicity.invalid_aws_creds"),
        ]
        duplicity.validate_backend()
        mock_clear_flag.assert_has_calls(calls=expected_calls)
        mock_set_flag.assert_not_called()

    @pytest.mark.parametrize(
        "key_id,secret_key", [("some_id", ""), ("", "some_key"), ("", "")]
    )
    @patch("duplicity.set_flag")
    @patch("duplicity.clear_flag")
    @patch("duplicity.config")
    def test_invalid_backend_s3(
        self, mock_config, mock_clear_flag, mock_set_flag, key_id, secret_key
    ):
        """Verify invalid s3 backend."""
        backend = "s3"
        side_effects = [backend, key_id, secret_key]
        mock_config.get.side_effect = side_effects
        duplicity.validate_backend()
        mock_clear_flag.assert_called_with("duplicity.invalid_backend")
        mock_set_flag.assert_called_with("duplicity.invalid_aws_creds")

    @patch("duplicity.set_flag")
    @patch("duplicity.clear_flag")
    @patch("duplicity.config")
    def test_invalid_backend_bad_backend(
        self, mock_config, mock_clear_flag, mock_set_flag
    ):
        """Verify invalid s3 backend."""
        backend = "bad_backend"
        mock_config.get.return_value = backend
        duplicity.validate_backend()
        mock_set_flag.assert_called_with("duplicity.invalid_backend")
        mock_clear_flag.assert_not_called()

    @patch("duplicity.set_flag")
    @patch("duplicity.clear_flag")
    @patch("duplicity.config")
    def test_validate_backend_success_azure(
        self, mock_config, mock_clear_flag, mock_set_flag
    ):
        """Verify valid azure backend."""
        backend = "azure"
        mock_config.get.side_effect = [backend, "azure_conn_string"]
        expected_calls = [
            call("duplicity.invalid_backend"),
            call("duplicity.invalid_azure_creds"),
        ]
        duplicity.validate_backend()
        mock_clear_flag.assert_has_calls(calls=expected_calls)
        mock_set_flag.assert_not_called()

    @pytest.mark.parametrize("conn_string", ["some_string", ""])
    @patch("duplicity.set_flag")
    @patch("duplicity.clear_flag")
    @patch("duplicity.config")
    def test_invalid_backend_azure(
        self, mock_config, mock_clear_flag, mock_set_flag, conn_string
    ):
        """Verify invalid azure backend."""
        backend = "azure"
        side_effects = [backend, conn_string]
        mock_config.get.side_effect = side_effects
        duplicity.validate_backend()
        mock_clear_flag.assert_any_call("duplicity.invalid_backend")

        if conn_string:
            mock_clear_flag.assert_called_with("duplicity.invalid_azure_creds")
            mock_set_flag.assert_not_called()
        else:
            mock_set_flag.assert_called_with("duplicity.invalid_azure_creds")


@pytest.mark.parametrize(
    "backup_dir,path_exists", [("my dir", False), ("my dir", True), ("", True)]
)
@patch("duplicity.config")
@patch("duplicity.os")
def test_create_aux_backup_directory(mock_os, mock_config, backup_dir, path_exists):
    """Verify backup directory creation."""
    mock_config.get.return_value = backup_dir
    mock_os.path.exists.return_value = path_exists
    duplicity.create_aux_backup_directory()
    if path_exists or not backup_dir:
        mock_os.makedirs.assert_not_called()
    else:
        mock_os.makedirs.assert_called_with(backup_dir)


class TestValidateCronFrequency:
    """Verify validation of cron frequency."""

    @pytest.mark.parametrize(
        "frequency,create_cron",
        [
            ("hourly", True),
            ("daily", True),
            ("weekly", True),
            ("monthly", True),
            ("manual", False),
        ],
    )
    @patch("duplicity.clear_flag")
    @patch("duplicity.set_flag")
    @patch("duplicity.config")
    def test_valid_cron_frequency(
        self, mock_config, mock_set_flag, mock_clear_flag, frequency, create_cron
    ):
        """Verify valid cron frequency."""
        set_flag_arg = (
            "duplicity.create_backup_cron"
            if create_cron
            else "duplicity.remove_backup_cron"
        )
        calls = [call(set_flag_arg)]
        mock_config.get.return_value = frequency
        duplicity.validate_cron_frequency()
        mock_set_flag.assert_has_calls(calls)
        mock_clear_flag.assert_called_with("duplicity.invalid_backup_frequency")

    @patch("duplicity.croniter")
    @patch("duplicity.clear_flag")
    @patch("duplicity.set_flag")
    @patch("duplicity.config")
    def test_valid_cron_string(
        self, mock_config, mock_set_flag, mock_clear_flag, mock_croniter
    ):
        """Verify valid cron frequency."""
        valid_cron_string = "* * * * *"
        mock_config.get.return_value = valid_cron_string
        calls = [call("duplicity.create_backup_cron")]
        duplicity.validate_cron_frequency()
        mock_croniter.croniter.assert_called_with(valid_cron_string)
        mock_set_flag.assert_has_calls(calls)
        mock_clear_flag.assert_called_with("duplicity.invalid_backup_frequency")

    @pytest.mark.parametrize(
        "raise_error",
        [CroniterBadDateError, CroniterNotAlphaError, CroniterBadCronError],
    )
    @patch("duplicity.croniter.croniter")
    @patch("duplicity.clear_flag")
    @patch("duplicity.set_flag")
    @patch("duplicity.config")
    def test_invalid_cron_string(
        self, mock_config, mock_set_flag, mock_clear_flag, mock_croniter, raise_error
    ):
        """Verify invalid cron frequency."""
        invalid_cron_string = "* * * *"
        mock_config.get.return_value = invalid_cron_string
        mock_croniter.side_effect = raise_error
        clear_flag_calls = [call("duplicity.create_backup_cron")]
        duplicity.validate_cron_frequency()
        mock_clear_flag.assert_has_calls(clear_flag_calls)
        mock_set_flag.assert_called_with("duplicity.invalid_backup_frequency")


class TestValidateRetention:
    """Verify validation of retention period settings and related functions."""

    @pytest.mark.parametrize(
        "frequency,is_valid_golden",
        [
            ("hourly", True),
            ("daily", True),
            ("* * * * *", True),
            ("* * * *", False),
        ],
    )
    def test_is_valid_deletion_frequency(self, frequency, is_valid_golden):
        """Verify valid deletion cron frequency."""
        assert duplicity.is_valid_deletion_frequency(frequency) == is_valid_golden

    @pytest.mark.parametrize(
        "retention,is_valid_golden",
        [
            ("30d", True),
            ("7d", True),
            ("manual", True),
            ("1h", True),
            ("99h", True),
            ("7D", False),
            ("3h7d", False),
            ("0d", False),
        ],
    )
    def test_is_valid_retention_period_valid(self, retention, is_valid_golden):
        """Verify valid retention period."""
        assert duplicity.is_valid_retention_period(retention) == is_valid_golden

    @pytest.mark.parametrize(
        "retention,frequency,is_valid_retention,is_valid_deletion_freq",
        [
            ("30d", "daily", True, True),
            ("30d", "* *", True, False),
            ("x", "* *", False, False),
            ("x", "daily", False, True),
        ],
    )
    @patch("duplicity.clear_flag")
    @patch("duplicity.set_flag")
    @patch("duplicity.config")
    def test_validate_retention_policy(
        self,
        mock_config,
        mock_set_flag,
        mock_clear_flag,
        retention,
        frequency,
        is_valid_retention,
        is_valid_deletion_freq,
    ):
        """Verify valid retention functionality."""
        mock_config.get.side_effect = [retention, frequency]
        duplicity.validate_retention_policy()
        clear_calls = []
        set_calls = []
        if is_valid_retention:
            clear_calls.append(call("duplicity.invalid_retention_period"))
            if is_valid_deletion_freq:
                set_calls.append(call("duplicity.create_deletion_cron"))
                clear_calls.append(call("duplicity.invalid_deletion_frequency"))
            else:
                set_calls.append(call("duplicity.remove_deletion_cron"))
                set_calls.append(call("duplicity.invalid_deletion_frequency"))
        else:
            set_calls.append(call("duplicity.remove_deletion_cron"))
            set_calls.append(call("duplicity.invalid_retention_period"))
        mock_clear_flag.assert_has_calls(clear_calls)
        mock_set_flag.assert_has_calls(set_calls)

    @patch("duplicity.clear_flag")
    @patch("duplicity.set_flag")
    @patch("duplicity.config")
    def test_validate_retention_policy_manual(
        self, mock_config, mock_set_flag, mock_clear_flag
    ):
        """Verify valid retention functionality against manual configuration."""
        mock_config.get.return_value = "manual"
        duplicity.validate_retention_policy()
        clear_calls = [
            call("duplicity.invalid_retention_period"),
            call("duplicity.invalid_deletion_frequency"),
        ]
        mock_clear_flag.assert_has_calls(clear_calls)
        mock_set_flag.assert_called_with("duplicity.remove_deletion_cron")


class TestUpdateKnownHostKey:
    """Verify updating known host key."""

    @patch("duplicity.helper")
    @patch("duplicity.hookenv")
    @patch("duplicity.config")
    def test_update_known_host_key_set(self, mock_config, mock_hookenv, mock_helper):
        """Verify setting known host key."""
        host_key = "somekey"
        mock_config.get.return_value = host_key
        duplicity.update_known_host_key()
        mock_hookenv.status_set.assert_called_with(
            workload_state="maintenance", message="Updating known_host_key"
        )
        mock_helper.update_known_host_file.assert_called_with(host_key)

    @patch("duplicity.helper")
    @patch("duplicity.config")
    def test_update_known_host_key_unset(self, mock_config, mock_helper):
        """Verify unsetting known host key."""
        mock_config.get.return_value = ""
        duplicity.update_known_host_key()
        mock_helper.update_known_host_file.assert_not_called()


@pytest.mark.parametrize(
    "remote_backup_url,is_valid", [("", False), ("some.url", True)]
)
@patch("duplicity.clear_flag")
@patch("duplicity.set_flag")
@patch("duplicity.config")
def test_check_remote_backup_url(
    mock_config, mock_set_flag, mock_clear_flag, remote_backup_url, is_valid
):
    """Verify remote backup url."""
    mock_config.get.return_value = remote_backup_url
    duplicity.check_remote_backup_url()
    if is_valid:
        mock_clear_flag.assert_called_with("duplicity.invalid_backend")
    else:
        mock_set_flag.assert_called_with("duplicity.invalid_backend")


@pytest.mark.parametrize(
    "encryption_passphrase,gpg_key,disable_encryption,valid",
    [
        ("e_pass", None, False, True),
        (None, "GPG", False, True),
        (None, None, True, True),
        (None, None, False, False),
    ],
)
@patch("duplicity.set_flag")
@patch("duplicity.clear_flag")
@patch("duplicity.config")
def test_validate_encryption_method(
    mock_config,
    mock_clear_flag,
    mock_set_flag,
    encryption_passphrase,
    gpg_key,
    disable_encryption,
    valid,
):
    """Verify encryption method."""
    mock_config.get.side_effect = [encryption_passphrase, gpg_key, disable_encryption]
    duplicity.validate_encryption_method()
    if valid:
        mock_clear_flag.assert_called_with("duplicity.invalid_encryption_method")
    else:
        mock_set_flag.assert_called_with("duplicity.invalid_encryption_method")


class TestCheckStatus:
    """Verify duplicity check status."""

    @patch("duplicity.hookenv")
    def test_check_status(self, mock_hookenv):
        """Verify duplicity check status."""
        duplicity.check_status()
        mock_hookenv.atexit.assert_called_with(duplicity.assess_status)

    @pytest.mark.parametrize(
        "invalid_flag,message,index",
        [
            (
                "duplicity.invalid_remote_backup_url",
                'Backup path is required. Set config for "remote_backup_url"',
                0,
            ),
            ("duplicity.invalid_backend", 'Unrecognized backend "{}"', 1),
            (
                "duplicity.invalid_aws_creds",
                'S3 backups require "aws_access_key_id" '
                'and "aws_secret_access_key" to be set',
                2,
            ),
            (
                "duplicity.invalid_azure_creds",
                'Azure backups require "azure_connection_string" ',
                3,
            ),
            (
                "duplicity.invalid_secure_backend_opts",
                "{} backend requires known_host_key "
                'and either "remote_password" or "private_ssh_key" to be set',
                4,
            ),
            (
                "duplicity.invalid_rsync_key",
                "rsync backend requires private_ssh_key. remote_password auth "
                "not supported",
                5,
            ),
            (
                "duplicity.invalid_encryption_method",
                "Must set either an encryption passphrase, "
                "GPG public key, or disable encryption",
                6,
            ),
            (
                "duplicity.invalid_private_ssh_key",
                "Invalid private_ssh_key. ensure that key is base64 encoded",
                7,
            ),
            (
                "duplicity.invalid_backup_frequency",
                'Invalid value "{}" for "backup_frequency"',
                8,
            ),
            (
                "duplicity.invalid_retention_period",
                'Invalid value "{}" for "retention_period"',
                9,
            ),
            (
                "duplicity.invalid_deletion_frequency",
                'Invalid value "{}" for "deletion_frequency"',
                10,
            ),
        ],
    )
    @patch("duplicity.is_flag_set")
    @patch("duplicity.hookenv")
    @patch("duplicity.config")
    def test_blocked_assess_status(
        self, mock_config, mock_hookenv, mock_is_flag_set, invalid_flag, message, index
    ):
        """Verify duplicity check status when unit is blocked."""
        side_effects = [False for _ in range(index)] + [True]
        mock_is_flag_set.side_effect = side_effects
        some_val = "some_val"
        mock_config.get.return_value = some_val
        duplicity.assess_status()
        mock_hookenv.status_set.assert_called_with(
            workload_state="blocked", message=message.format(some_val)
        )

    @patch("duplicity.is_flag_set")
    @patch("duplicity.hookenv")
    def test_good_assess_status(self, mock_hookenv, mock_is_flag_set):
        """Verify duplicity check status when unit is active."""
        mock_is_flag_set.return_value = False
        duplicity.assess_status()
        mock_hookenv.status_set.assert_has_calls(calls=[call("active", "Ready")])


@patch("duplicity.hookenv")
@patch("duplicity.clear_flag")
@patch("duplicity.helper")
def test_create_backup_cron(mock_helper, mock_clear_flag, mock_hookenv):
    """Verify creation cron job."""
    hookenv_calls = [
        call("maintenance", "Rendering duplicity crontab"),
        call("active", "Rendered duplicity crontab"),
    ]
    duplicity.create_backup_cron()
    mock_hookenv.status_set.assert_has_calls(hookenv_calls)
    mock_helper.setup_backup_cron.assert_called_once()
    mock_clear_flag.assert_called_with("duplicity.create_backup_cron")


@patch("duplicity.hookenv")
@patch("duplicity.clear_flag")
@patch("duplicity.helper")
def test_create_deletion_cron(mock_helper, mock_clear_flag, mock_hookenv):
    """Verify creation cron job."""
    hookenv_calls = [
        call("maintenance", "Rendering duplicity crontab for deletion"),
        call("active", "Rendered duplicity crontab for deletion"),
    ]
    duplicity.create_deletion_cron()
    mock_hookenv.status_set.assert_has_calls(hookenv_calls)
    mock_helper.setup_deletion_cron.assert_called_once()
    mock_clear_flag.assert_called_with("duplicity.create_deletion_cron")


@patch("duplicity.hookenv")
@patch("duplicity.safe_remove_backup_cron")
@patch("duplicity.clear_flag")
def test_remove_backup_cron(
    mock_clear_flag, mock_safe_remove_backup_cron, mock_hookenv
):
    """Verify removing cron job."""
    duplicity.remove_backup_cron()
    mock_safe_remove_backup_cron.assert_called_once()
    mock_clear_flag.assert_called_with("duplicity.remove_backup_cron")


@patch("duplicity.hookenv")
@patch("duplicity.safe_remove_deletion_cron")
@patch("duplicity.clear_flag")
def test_remove_deletion_cron(
    mock_clear_flag, mock_safe_remove_deletion_cron, mock_hookenv
):
    """Verify removing cron job."""
    duplicity.remove_deletion_cron()
    mock_safe_remove_deletion_cron.assert_called_once()
    mock_clear_flag.assert_called_with("duplicity.remove_deletion_cron")


class TestUpdatePrivateSshKey:
    """Verify updating private ssh key."""

    @pytest.mark.parametrize(
        "check_key, converted_pem, expected_key, ubuntu_release",
        [
            (True, "a_pem_key", "a_pem_key", "focal"),
            (False, "a_pem_key", "a_decoded_key", "focal"),
            (True, "a_pem_key", "a_decoded_key", "jammy"),
            (False, "a_pem_key", "a_decoded_key", "jammy"),
        ],
    )
    @patch("os.chmod")
    @patch("duplicity.host.lsb_release")
    @patch("duplicity.helper")
    @patch("duplicity.clear_flag")
    @patch("duplicity.base64")
    @patch("duplicity.hookenv")
    def test_update_key_success(
        self,
        mock_config,
        mock_base64,
        mock_clear_flag,
        mock_helper,
        mock_release,
        os_chmod,
        check_key,
        converted_pem,
        expected_key,
        ubuntu_release,
    ):
        """Verify updating key is successful."""
        private_key = "a_key"
        decoded_key = "a_decoded_key"
        mock_config.get.return_value = private_key
        mock_base64.b64decode.return_value.decode.return_value = decoded_key
        mock_helper.check_key_rsa_openssh.return_value = check_key
        mock_helper.convert_key_to_pem.return_value = converted_pem
        mock_release.return_value = {"DISTRIB_CODENAME": ubuntu_release}
        with patch("duplicity.open", mock_open()) as m_open:
            duplicity.update_private_ssh_key()
        mock_base64.b64decode.return_value.decode.assert_called_once()
        m_open.assert_called_with(duplicity.PRIVATE_SSH_KEY_PATH, "w")
        handler = m_open()
        handler.write.assert_called_with(expected_key)
        mock_clear_flag.assert_called_with("duplicity.invalid_private_ssh_key")
        os_chmod.assert_called_with("/root/.ssh/duplicity_id_rsa", 0o600)

    @pytest.mark.parametrize("path_exists", [True, False])
    @patch("duplicity.clear_flag")
    @patch("duplicity.os")
    @patch("duplicity.config")
    def test_update_key_no_key(
        self, mock_config, mock_os, mock_clear_flag, path_exists
    ):
        """Verify updating key fails."""
        mock_config.get.return_value = ""
        mock_os.path.exists.return_value = path_exists
        duplicity.update_private_ssh_key()
        assert mock_os.remove.called == path_exists
        mock_clear_flag.assert_called_with("duplicity.invalid_private_ssh_key")

    @patch("duplicity.clear_flag")
    @patch("duplicity.set_flag")
    @patch("duplicity.config")
    def test_update_key_fail(self, mock_config, mock_set_flag, mock_clear_flag):
        """Verify updating key fails."""
        mock_config.get.return_value = "invalid_key"
        duplicity.update_private_ssh_key()
        mock_set_flag.assert_called_with("duplicity.invalid_private_ssh_key")
        mock_clear_flag.assert_not_called()


@patch("duplicity.set_flag")
@patch("duplicity.render_checks")
def test_initial_nrpe_config(mock_render_checks, mock_set_flag):
    """Verify nrpe checks rendering is called."""
    duplicity.initial_nrpe_config()
    mock_set_flag.assert_called_with("nrpe-external-master.initial-config")
    mock_render_checks.assert_called_once()


@pytest.mark.parametrize("plugins_dir_path_exists", [True, False])
@patch("duplicity.set_flag")
@patch("duplicity.NRPE")
@patch("duplicity.host")
@patch("duplicity.os")
@patch("duplicity.hookenv")
def test_render_checks(
    mock_hookenv, mock_os, mock_host, nrpe, mock_set_flag, plugins_dir_path_exists
):
    """Verify nrpe checks are rendered correctly."""
    charm_dir = "some_dir"
    charm_plugin_dir = "charm_plugin_dir"
    check_command = "check_command"
    mock_hookenv.charm_dir.return_value = charm_dir
    mock_os.path.join.side_effect = [charm_plugin_dir, check_command]
    mock_os.path.exists.return_value = plugins_dir_path_exists
    os_join_calls = [
        call(charm_dir, "scripts", "plugins/"),
        call(duplicity.PLUGINS_DIR, "check_backup_status.py"),
    ]
    mock_nrpe = MagicMock()
    nrpe.return_value = mock_nrpe
    duplicity.render_checks()
    mock_os.path.join.assert_has_calls(os_join_calls)
    assert mock_os.makedirs.called != plugins_dir_path_exists
    mock_host.rsync.assert_called_with(charm_plugin_dir, duplicity.PLUGINS_DIR)
    mock_nrpe.add_check.assert_called_with(
        check_cmd=check_command, shortname="backups", description=ANY
    )
    mock_nrpe.write.assert_called_once()
    mock_set_flag.assert_called_with("nrpe-external-master.configured")


@patch("duplicity.NRPE")
@patch("duplicity.clear_flag")
def test_remove_nrpe_checks(mock_clear_flag, nrpe):
    """Verify removing nrpe checks."""
    mock_nrpe = MagicMock()
    nrpe.return_value = mock_nrpe
    duplicity.remove_nrpe_checks()
    mock_nrpe.remove_check.assert_called_with(shortname="backups")
    mock_clear_flag.assert_called_with("nrpe-external-master.configured")


@patch("duplicity.safe_remove_backup_cron")
@patch("duplicity.safe_remove_deletion_cron")
def test_stop(mock_safe_remove_backup_cron, mock_safe_remove_deletion_cron):
    """Verify stop hook."""
    duplicity.stop()
    mock_safe_remove_backup_cron.assert_called_once()
    mock_safe_remove_deletion_cron.assert_called_once()
