from unittest.mock import patch, call, ANY, mock_open, MagicMock, DEFAULT

import pytest
from croniter import CroniterBadCronError, CroniterBadDateError, CroniterNotAlphaError

with patch('lib_duplicity.DuplicityHelper') as helper_mock:
    with patch('charmhelpers.core.hookenv') as hookenv_mock:
        import duplicity


@patch('duplicity.hookenv')
@patch('duplicity.fetch')
@patch('duplicity.set_flag')
def test_install_duplicity(mock_set_flag, mock_fetch, mock_hookenv):
    hookenv_calls = [call('maintenance', 'Installing duplicity'), call('active', '')]
    fetch_calls = [call(x) for x in ['duplicity', 'python-paramiko', 'python-boto', 'lftp']]
    duplicity.install_duplicity()
    mock_hookenv.status_set.assert_has_calls(hookenv_calls)
    mock_fetch.apt_install.assert_has_calls(fetch_calls)
    mock_set_flag.assert_called_with('duplicity.installed')


class TestValidateBackend:
    @pytest.mark.parametrize('backend,', ['ftp', 'file'])
    @patch('duplicity.set_flag')
    @patch('duplicity.clear_flag')
    @patch('duplicity.config')
    def test_validate_backend_success_not_secured(
            self, mock_config, mock_clear_flag, mock_set_flag, backend):
        mock_config.get.return_value = backend
        duplicity.validate_backend()
        mock_clear_flag.assert_called_with('duplicity.invalid_backend')
        mock_set_flag.assert_not_called()

    @pytest.mark.parametrize('backend,remote_password,ssh_key', [
        ('scp', 'remote-pass', None),
        ('scp', None, 'ssh_key'),
        ('rsync', None, 'ssh_key'),
        ('sftp', 'remote-pass', None),
        ('sftp', None, 'ssh_key'),
    ])
    @patch('duplicity.set_flag')
    @patch('duplicity.clear_flag')
    @patch('duplicity.config')
    def test_validate_backend_success_secured(
            self, mock_config, mock_clear_flag, mock_set_flag, backend, remote_password, ssh_key):
        known_host_key = 'host_key'
        if backend == 'rsync':
            side_effects = [backend, ssh_key, known_host_key,
                            remote_password, ssh_key]
        else:
            side_effects = [backend, known_host_key, remote_password, ssh_key]
        mock_config.get.side_effect = side_effects
        duplicity.validate_backend()
        mock_set_flag.assert_not_called()
        mock_clear_flag.assert_called_with('duplicity.invalid_secure_backend_opts')

    @patch('duplicity.set_flag')
    @patch('duplicity.clear_flag')
    @patch('duplicity.config')
    def test_invalid_backend_secured_no_private_ssh_key_rsync(
            self, mock_config, mock_clear_flag, mock_set_flag):
        backend = 'rsync'
        known_host_key = 'host_key'
        remote_password = 'remote-pass'
        mock_config.get.side_effect = [backend, None, known_host_key,
                                       remote_password, None]
        duplicity.validate_backend()
        mock_clear_flag.assert_called_with('duplicity.invalid_backend')
        mock_set_flag.assert_called_with('duplicity.invalid_rsync_key')

    @pytest.mark.parametrize('backend', ['scp', 'rsync'])
    @patch('duplicity.set_flag')
    @patch('duplicity.clear_flag')
    @patch('duplicity.config')
    def test_invalid_backend_secured_no_host_key(
            self, mock_config, mock_clear_flag, mock_set_flag, backend):
        if backend == 'rsync':
            mock_config.get.side_effect = [backend, 'ssk_key', None, None, 'ssh_key']
        else:
            mock_config.get.side_effect = [backend, None, None, None]
        duplicity.validate_backend()
        mock_set_flag.assert_called_with('duplicity.invalid_secure_backend_opts')
        if backend == 'rsync':
            mock_clear_flag.assert_called_with('duplicity.invalid_rsync_key')
        else:
            mock_clear_flag.assert_called_with('duplicity.invalid_backend')

    @patch('duplicity.set_flag')
    @patch('duplicity.clear_flag')
    @patch('duplicity.config')
    def test_validate_backend_success_s3(self, mock_config, mock_clear_flag, mock_set_flag):
        backend = 's3'
        mock_config.get.side_effect = [backend, 'aws_id', 'aws_secret']
        expected_calls = [call('duplicity.invalid_backend'), call('duplicity.invalid_aws_creds')]
        duplicity.validate_backend()
        mock_clear_flag.assert_has_calls(calls=expected_calls)
        mock_set_flag.assert_not_called()

    @pytest.mark.parametrize('key_id,secret_key', [
        ('some_id', ''),
        ('', 'some_key'),
        ('', ''),
    ])
    @patch('duplicity.set_flag')
    @patch('duplicity.clear_flag')
    @patch('duplicity.config')
    def test_invalid_backend_s3(self, mock_config, mock_clear_flag, mock_set_flag, key_id, secret_key):
        backend = 's3'
        side_effects = [backend, key_id, secret_key]
        mock_config.get.side_effect = side_effects
        duplicity.validate_backend()
        mock_clear_flag.assert_called_with('duplicity.invalid_backend')
        mock_set_flag.assert_called_with('duplicity.invalid_aws_creds')

    @patch('duplicity.set_flag')
    @patch('duplicity.clear_flag')
    @patch('duplicity.config')
    def test_invalid_backend_bad_backend(self, mock_config, mock_clear_flag, mock_set_flag):
        backend = 'bad_backend'
        mock_config.get.return_value = backend
        duplicity.validate_backend()
        mock_set_flag.assert_called_with('duplicity.invalid_backend')
        mock_clear_flag.assert_not_called()


@pytest.mark.parametrize('backup_dir,path_exists', [
    ('my dir', False),
    ('my dir', True),
    ('', True),
])
@patch('duplicity.config')
@patch('duplicity.os')
def test_create_aux_backup_directory(mock_os, mock_config, backup_dir, path_exists):
    mock_config.get.return_value = backup_dir
    mock_os.path.exists.return_value = path_exists
    duplicity.create_aux_backup_directory()
    if path_exists or not backup_dir:
        mock_os.makedirs.assert_not_called()
    else:
        mock_os.makedirs.assert_called_with(backup_dir)


class TestValidateCronFrequency:
    @pytest.mark.parametrize('frequency,create_cron', [
        ('hourly', True),
        ('daily', True),
        ('weekly', True),
        ('monthly', True),
        ('manual', False),
    ])
    @patch('duplicity.clear_flag')
    @patch('duplicity.set_flag')
    @patch('duplicity.config')
    def test_valid_cron_frequency(self, mock_config, mock_set_flag, mock_clear_flag, frequency, create_cron):
        set_flag_arg = 'duplicity.create_backup_cron' if create_cron else 'duplicity.remove_backup_cron'
        calls = [call(set_flag_arg)]
        mock_config.get.return_value = frequency
        duplicity.validate_cron_frequency()
        mock_set_flag.assert_has_calls(calls)
        mock_clear_flag.assert_called_with('duplicity.invalid_backup_frequency')

    @patch('duplicity.croniter')
    @patch('duplicity.clear_flag')
    @patch('duplicity.set_flag')
    @patch('duplicity.config')
    def test_valid_cron_string(self, mock_config, mock_set_flag, mock_clear_flag, mock_croniter):
        valid_cron_string = '* * * * *'
        mock_config.get.return_value = valid_cron_string
        calls = [call('duplicity.create_backup_cron')]
        duplicity.validate_cron_frequency()
        mock_croniter.croniter.assert_called_with(valid_cron_string)
        mock_set_flag.assert_has_calls(calls)
        mock_clear_flag.assert_called_with('duplicity.invalid_backup_frequency')

    @pytest.mark.parametrize('raise_error', [CroniterBadDateError, CroniterNotAlphaError, CroniterBadCronError])
    @patch('duplicity.croniter.croniter')
    @patch('duplicity.clear_flag')
    @patch('duplicity.set_flag')
    @patch('duplicity.config')
    def test_invalid_cron_string(self, mock_config, mock_set_flag, mock_clear_flag, mock_croniter, raise_error):
        invalid_cron_string = '* * * *'
        mock_config.get.return_value = invalid_cron_string
        mock_croniter.side_effect = raise_error
        clear_flag_calls = [call('duplicity.create_backup_cron')]
        duplicity.validate_cron_frequency()
        mock_clear_flag.assert_has_calls(clear_flag_calls)
        mock_set_flag.assert_called_with('duplicity.invalid_backup_frequency')


class TestUpdateKnownHostKey:
    @patch('duplicity.helper')
    @patch('duplicity.hookenv')
    @patch('duplicity.config')
    def test_update_known_host_key_set(self, mock_config, mock_hookenv, mock_helper):
        host_key = 'somekey'
        mock_config.get.return_value = host_key
        duplicity.update_known_host_key()
        mock_hookenv.status_set.assert_called_with(
            workload_state='maintenance',
            message='Updating known_host_key'
        )
        mock_helper.update_known_host_file.assert_called_with(host_key)

    @patch('duplicity.helper')
    @patch('duplicity.config')
    def test_update_known_host_key_unset(self, mock_config, mock_helper):
        mock_config.get.return_value = ''
        duplicity.update_known_host_key()
        mock_helper.update_known_host_file.assert_not_called()


@pytest.mark.parametrize('remote_backup_url,is_valid', [
    ('', False),
    ('some.url', True)
])
@patch('duplicity.clear_flag')
@patch('duplicity.set_flag')
@patch('duplicity.config')
def test_check_remote_backup_url(mock_config, mock_set_flag, mock_clear_flag, remote_backup_url, is_valid):
    mock_config.get.return_value = remote_backup_url
    duplicity.check_remote_backup_url()
    if is_valid:
        mock_clear_flag.assert_called_with('duplicity.invalid_backend')
    else:
        mock_set_flag.assert_called_with('duplicity.invalid_backend')


@pytest.mark.parametrize('encryption_passphrase,gpg_key,disable_encryption,valid', [
    ('e_pass', None, False, True),
    (None, 'GPG', False, True),
    (None, None, True, True),
    (None, None, False, False),
])
@patch('duplicity.set_flag')
@patch('duplicity.clear_flag')
@patch('duplicity.config')
def test_validate_encryption_method(
        mock_config, mock_clear_flag, mock_set_flag, encryption_passphrase, gpg_key, disable_encryption, valid):
    mock_config.get.side_effect = [encryption_passphrase, gpg_key, disable_encryption]
    duplicity.validate_encryption_method()
    if valid:
        mock_clear_flag.assert_called_with('duplicity.invalid_encryption_method')
    else:
        mock_set_flag.assert_called_with('duplicity.invalid_encryption_method')


class TestCheckStatus:
    @patch('duplicity.hookenv')
    def test_check_status(self, mock_hookenv):
        duplicity.check_status()
        mock_hookenv.atexit.assert_called_with(duplicity.assess_status)

    @pytest.mark.parametrize('invalid_flag,message,index', [
        ('duplicity.invalid_remote_backup_url', 'Backup path is required. Set config for "remote_backup_url"', 0),
        ('duplicity.invalid_backend', 'Unrecognized backend "{}"', 1),
        ('duplicity.invalid_aws_creds',
         'S3 backups require "aws_access_key_id" and "aws_secret_access_key" to be set', 2),
        ('duplicity.invalid_secure_backend_opts',
         '{} backend requires known_host_key and either "remote_password" or "private_ssh_key" to be set', 3),
        ('duplicity.invalid_rsync_key',
         'rsync backend requires private_ssh_key. remote_password auth not supported', 4),
        ('duplicity.invalid_encryption_method',
         'Must set either an encryption passphrase, GPG public key, or disable encryption', 5),
        ('duplicity.invalid_private_ssh_key', 'Invalid private_ssh_key. ensure that key is base64 encoded', 6),
        ('duplicity.invalid_backup_frequency', 'Invalid value "{}" for "backup_frequency"', 7),
    ])
    @patch('duplicity.is_flag_set')
    @patch('duplicity.hookenv')
    @patch('duplicity.config')
    def test_blocked_assess_status(self, mock_config, mock_hookenv, mock_is_flag_set, invalid_flag, message, index):
        side_effects = [False for _ in range(index)] + [True]
        mock_is_flag_set.side_effect = side_effects
        some_val = 'some_val'
        mock_config.get.return_value = some_val
        duplicity.assess_status()
        mock_hookenv.status_set.assert_called_with(
            workload_state='blocked',
            message=message.format(some_val)
        )

    @patch('duplicity.is_flag_set')
    @patch('duplicity.hookenv')
    def test_good_assess_status(self, mock_hookenv, mock_is_flag_set):
        mock_is_flag_set.return_value = False
        duplicity.assess_status()
        mock_hookenv.status_set.assert_has_calls(calls=[call('active', 'Ready')])


@patch('duplicity.hookenv')
@patch('duplicity.clear_flag')
@patch('duplicity.helper')
def test_create_backup_cron(mock_helper, mock_clear_flag, mock_hookenv):
    hookenv_calls = [call('maintenance', 'Rendering duplicity crontab'),
                     call('active', 'Rendered duplicity crontab')]
    duplicity.create_backup_cron()
    mock_hookenv.status_set.assert_has_calls(hookenv_calls)
    mock_helper.setup_backup_cron.assert_called_once()
    mock_clear_flag.assert_called_with('duplicity.create_backup_cron')


@patch('duplicity.hookenv')
@patch('duplicity.safe_remove_backup_cron')
@patch('duplicity.clear_flag')
def test_remove_backup_cron(mock_clear_flag, mock_safe_remove_backup_cron, mock_hookenv):
    duplicity.remove_backup_cron()
    mock_safe_remove_backup_cron.assert_called_once()
    mock_clear_flag.assert_called_with('duplicity.remove_backup_cron')


class TestUpdatePrivateSshKey:
    @patch('duplicity.clear_flag')
    @patch('duplicity.base64')
    @patch('duplicity.hookenv')
    def test_update_key_success(self, mock_config, mock_base64, mock_clear_flag):
        private_key = 'a_key'
        decoded_key = 'a_decoded_key'
        mock_config.get.return_value = private_key
        mock_base64.b64decode.return_value.decode.return_value = decoded_key
        with patch('duplicity.open', mock_open()) as m_open:
            duplicity.update_private_ssh_key()
        mock_base64.b64decode.return_value.decode.assert_called_once()
        m_open.assert_called_with(duplicity.PRIVATE_SSH_KEY_PATH, 'w')
        handler = m_open()
        handler.write.assert_called_with(decoded_key)
        mock_clear_flag.assert_called_with('duplicity.invalid_private_ssh_key')

    @pytest.mark.parametrize('path_exists', [True, False])
    @patch('duplicity.clear_flag')
    @patch('duplicity.os')
    @patch('duplicity.config')
    def test_update_key_no_key(self, mock_config, mock_os, mock_clear_flag, path_exists):
        mock_config.get.return_value = ''
        mock_os.path.exists.return_value = path_exists
        duplicity.update_private_ssh_key()
        assert mock_os.remove.called == path_exists
        mock_clear_flag.assert_called_with('duplicity.invalid_private_ssh_key')

    @patch('duplicity.clear_flag')
    @patch('duplicity.set_flag')
    @patch('duplicity.config')
    def test_update_key_fail(self, mock_config, mock_set_flag, mock_clear_flag):
        mock_config.get.return_value = 'invalid_key'
        duplicity.update_private_ssh_key()
        mock_set_flag.assert_called_with('duplicity.invalid_private_ssh_key')
        mock_clear_flag.assert_not_called()


@patch('duplicity.set_flag')
@patch('duplicity.render_checks')
def test_initial_nrpe_config(mock_render_checks, mock_set_flag):
    duplicity.initial_nrpe_config()
    mock_set_flag.assert_called_with('nrpe-external-master.initial-config')
    mock_render_checks.assert_called_once()


@pytest.mark.parametrize('plugins_dir_path_exists', [True, False])
@patch('duplicity.set_flag')
@patch('duplicity.NRPE')
@patch('duplicity.host')
@patch('duplicity.os')
@patch('duplicity.hookenv')
def test_render_checks(mock_hookenv, mock_os, mock_host, mock_NRPE, mock_set_flag, plugins_dir_path_exists):
    charm_dir = 'some_dir'
    charm_plugin_dir = 'charm_plugin_dir'
    check_command = 'check_command'
    mock_hookenv.charm_dir.return_value = charm_dir
    mock_os.path.join.side_effect = [charm_plugin_dir, check_command]
    mock_os.path.exists.return_value = plugins_dir_path_exists
    os_join_calls = [call(charm_dir, 'scripts', 'plugins/'), call(duplicity.PLUGINS_DIR, 'check_backup_status.py')]
    mock_nrpe = MagicMock()
    mock_NRPE.return_value = mock_nrpe
    duplicity.render_checks()
    mock_os.path.join.assert_has_calls(os_join_calls)
    assert mock_os.makedirs.called != plugins_dir_path_exists
    mock_host.rsync.assert_called_with(charm_plugin_dir, duplicity.PLUGINS_DIR)
    mock_nrpe.add_check.assert_called_with(
        check_cmd=check_command, shortname='backups', description=ANY
    )
    mock_nrpe.write.assert_called_once()
    mock_set_flag.assert_called_with('nrpe-external-master.configured')


@patch('duplicity.NRPE')
@patch('duplicity.clear_flag')
def test_remove_nrpe_checks(mock_clear_flag, mock_NRPE):
    mock_nrpe = MagicMock()
    mock_NRPE.return_value = mock_nrpe
    duplicity.remove_nrpe_checks()
    mock_nrpe.remove_check.assert_called_with(shortname='backups')
    mock_clear_flag.assert_called_with('nrpe-external-master.configured')


@patch('duplicity.safe_remove_backup_cron')
def test_stop(mock_safe_remove_backup_cron):
    duplicity.stop()
    mock_safe_remove_backup_cron.assert_called_once()
