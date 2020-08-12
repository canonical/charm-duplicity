from unittest.mock import patch
from subprocess import CalledProcessError

import pytest

with patch('lib_duplicity.DuplicityHelper') as mock_duplicity_helper:
    import actions


class TestActions:
    @pytest.mark.parametrize('error_path_exists', [True, False])
    @patch('actions.do_backup')
    @patch('actions.clear_flag')
    @patch('actions.os.path.exists')
    @patch('actions.os.remove')
    def test_action_run_success(self, mock_remove, mock_exists, mock_clear_flag, mock_do_backup, error_path_exists):
        action_args = ['actions/do-backup']
        mock_exists.return_value = error_path_exists
        actions.ACTIONS['do-backup'] = mock_do_backup
        actions.main(action_args)
        mock_do_backup.assert_called_with(action_args)
        mock_clear_flag.assert_called()
        assert mock_remove.called == error_path_exists

    @patch('actions.do_backup')
    @patch('actions.clear_flag')
    @patch('actions.os.remove')
    def test_action_run_undefined_action(self, mock_remove, mock_clear_flag, mock_do_backup):
        action_args = ['actions/bad_action']
        actions.ACTIONS['do-backup'] = mock_do_backup
        result = actions.main(action_args)
        assert 'bad_action' in result and 'undefined' in result
        mock_do_backup.assert_not_called()
        mock_clear_flag.assert_not_called()

    @pytest.mark.parametrize('exception_raised,expected_fail_contains', [
        (CalledProcessError(returncode=2, output='my-error-output'.encode('utf-8'), cmd='cmd'),
         ['2', 'my-error-output']),
        (Exception('generic exception'), ['generic exception'])
    ])
    @patch('actions.hookenv')
    @patch('actions.do_backup')
    @patch('actions.clear_flag')
    @patch('actions.os.remove')
    def test_action_run_error(
            self, mock_remove, mock_clear_flag, mock_do_backup, mock_hookenv, exception_raised, expected_fail_contains):
        action_args = ['actions/do-backup']
        mock_do_backup.side_effect = exception_raised
        actions.ACTIONS['do-backup'] = mock_do_backup
        try:
            actions.main(action_args)
        except Exception as e:
            assert type(exception_raised) == type(e)
            for expected_contain in expected_fail_contains:
                assert expected_contain in str(e)
        mock_hookenv.function_fail.assert_called()
        mock_remove.assert_not_called()
        mock_clear_flag.assert_not_called()


class TestDoBackupAction:
    @patch('actions.helper')
    @patch('actions.hookenv')
    def test_do_backup(self, mock_hookenv, mock_helper):
        result = 'action_output'.encode('utf-8')
        mock_helper.do_backup.return_value = result
        expected_dict_input = dict(output=result.decode('utf-8'))
        actions.do_backup()
        mock_helper.do_backup.assert_called_once()
        mock_hookenv.function_set.called_with(expected_dict_input)
