"""Unit tests for charm actions."""
from subprocess import CalledProcessError
from unittest.mock import patch

import pytest

with patch("lib_duplicity.DuplicityHelper") as mock_duplicity_helper:
    import actions


class TestActions:
    """Unit tests for charm actions."""

    @pytest.mark.parametrize("error_path_exists", [True, False])
    @patch("actions.do_backup")
    @patch("actions.clear_flag")
    @patch("actions.os.path.exists")
    @patch("actions.os.remove")
    def test_action_run_success(
        self,
        mock_remove,
        mock_exists,
        mock_clear_flag,
        mock_do_backup,
        error_path_exists,
    ):
        """Verify valid action."""
        action_args = ["actions/do-backup"]
        mock_exists.return_value = error_path_exists
        actions.ACTIONS["do-backup"] = mock_do_backup
        actions.main(action_args)
        mock_do_backup.assert_called_with(action_args)
        mock_clear_flag.assert_called()
        assert mock_remove.called == error_path_exists

    @pytest.mark.parametrize("error_path_exists", [True, False])
    @patch("actions.list_current_files")
    @patch("actions.os.path.exists")
    @patch("actions.os.remove")
    def test_list_files_action_run_success(
        self,
        mock_remove,
        mock_exists,
        mock_list_current_files,
        error_path_exists,
    ):
        """Verify list-current-files action."""
        action_args = ["actions/list-current-files"]
        mock_exists.return_value = error_path_exists
        actions.ACTIONS["list-current-files"] = mock_list_current_files
        actions.main(action_args)
        mock_list_current_files.assert_called_with(action_args)
        assert mock_remove.called == error_path_exists

    @pytest.mark.parametrize("error_path_exists", [True, False])
    @patch("actions.remove_older_than")
    @patch("actions.os.path.exists")
    @patch("actions.os.remove")
    def test_remove_older_than_action_run_success(
        self,
        mock_remove,
        mock_exists,
        mock_remove_older_than,
        error_path_exists,
    ):
        """Verify remove_older_than action."""
        action_args = ["actions/remove_older_than"]
        mock_exists.return_value = error_path_exists
        actions.ACTIONS["remove_older_than"] = mock_remove_older_than
        actions.main(action_args)
        mock_remove_older_than.assert_called_with(action_args)
        assert mock_remove.called == error_path_exists

    @pytest.mark.parametrize("error_path_exists", [True, False])
    @patch("actions.remove_all_but_n_full")
    @patch("actions.os.path.exists")
    @patch("actions.os.remove")
    def test_remove_all_but_n_full_run_success(
        self,
        mock_remove,
        mock_exists,
        mock_remove_all_but_n_full,
        error_path_exists,
    ):
        """Verify remove_all_but_n_full action."""
        action_args = ["actions/remove_all_but_n_full"]
        mock_exists.return_value = error_path_exists
        actions.ACTIONS["remove_all_but_n_full"] = mock_remove_all_but_n_full
        actions.main(action_args)
        mock_remove_all_but_n_full.assert_called_with(action_args)
        assert mock_remove.called == error_path_exists

    @pytest.mark.parametrize("error_path_exists", [True, False])
    @patch("actions.remove_all_inc_of_but_n_full")
    @patch("actions.os.path.exists")
    @patch("actions.os.remove")
    def test_remove_all_inc_of_but_n_full_run_success(
        self,
        mock_remove,
        mock_exists,
        mock_remove_all_inc_of_but_n_full,
        error_path_exists,
    ):
        """Verify remove_all_inc_of_but_n_full action."""
        action_args = ["actions/remove_all_inc_of_but_n_full"]
        mock_exists.return_value = error_path_exists
        mock_temp = mock_remove_all_inc_of_but_n_full
        actions.ACTIONS["remove_all_inc_of_but_n_full"] = mock_temp
        actions.main(action_args)
        mock_remove_all_inc_of_but_n_full.assert_called_with(action_args)
        assert mock_remove.called == error_path_exists

    @patch("actions.do_backup")
    @patch("actions.clear_flag")
    @patch("actions.os.remove")
    def test_action_run_undefined_action(
        self, mock_remove, mock_clear_flag, mock_do_backup
    ):
        """Verify invalid action."""
        action_args = ["actions/bad_action"]
        actions.ACTIONS["do-backup"] = mock_do_backup
        result = actions.main(action_args)
        assert "bad_action" in result and "undefined" in result
        mock_do_backup.assert_not_called()
        mock_clear_flag.assert_not_called()

    @pytest.mark.parametrize(
        "exception_raised,expected_fail_contains",
        [
            (
                CalledProcessError(
                    returncode=2, output="my-error-output".encode("utf-8"), cmd="cmd"
                ),
                ["2", "my-error-output"],
            ),
            (Exception("generic exception"), ["generic exception"]),
        ],
    )
    @patch("actions.hookenv")
    @patch("actions.do_backup")
    @patch("actions.clear_flag")
    @patch("actions.os.remove")
    def test_action_run_error(
        self,
        mock_remove,
        mock_clear_flag,
        mock_do_backup,
        mock_hookenv,
        exception_raised,
        expected_fail_contains,
    ):
        """Verify action returns an error."""
        action_args = ["actions/do-backup"]
        mock_do_backup.side_effect = exception_raised
        actions.ACTIONS["do-backup"] = mock_do_backup
        try:
            actions.main(action_args)
        except Exception as e:
            assert type(exception_raised) == type(e)
            for expected_contain in expected_fail_contains:
                assert expected_contain in str(e)
        mock_hookenv.action_fail.assert_called()
        mock_remove.assert_not_called()
        mock_clear_flag.assert_not_called()


class TestDoBackupAction:
    """Verify do-backup action."""

    @patch("actions.helper")
    @patch("actions.hookenv")
    def test_do_backup(self, mock_hookenv, mock_helper):
        """Verify do-backup action."""
        result = "action_output".encode("utf-8")
        mock_helper.do_backup.return_value = result
        expected_dict_input = dict(output=result.decode("utf-8"))
        actions.do_backup()
        mock_helper.do_backup.assert_called_once()
        mock_hookenv.action_set.called_with(expected_dict_input)


class TestListCurrentFilesAction:
    """Verify list-current-files action."""

    @patch("actions.helper")
    @patch("actions.hookenv")
    def test_list_current_files(self, mock_hookenv, mock_helper):
        """Verify list-current-files action."""
        result = "action_output".encode("utf-8")
        mock_helper.list_current_files.return_value = result
        expected_dict_input = dict(output=result.decode("utf-8"))
        actions.list_current_files()
        mock_helper.list_current_files.assert_called_once()
        mock_hookenv.action_set.called_with(expected_dict_input)


class TestRemoveOlderThanAction:
    """Verify remove-older-than action."""

    @patch("actions.helper")
    @patch("actions.hookenv")
    def test_remove_older_than(self, mock_hookenv, mock_helper):
        """Verify remove-older-than action."""
        result = "action_output".encode("utf-8")
        mock_helper.remove_older_than.return_value = result
        expected_dict_input = dict(output=result.decode("utf-8"))
        actions.remove_older_than()
        mock_helper.remove_older_than.assert_called_once()
        mock_hookenv.action_set.called_with(expected_dict_input)


class TestRemoveAllButNFullAction:
    """Verify remove-all-but-n-full action."""

    @patch("actions.helper")
    @patch("actions.hookenv")
    def test_remove_all_but_n_full(self, mock_hookenv, mock_helper):
        """Verify remove-all-but-n-full action."""
        result = "action_output".encode("utf-8")
        mock_helper.remove_all_but_n_full.return_value = result
        expected_dict_input = dict(output=result.decode("utf-8"))
        actions.remove_all_but_n_full()
        mock_helper.remove_all_but_n_full.assert_called_once()
        mock_hookenv.action_set.called_with(expected_dict_input)


class TestRemoveAllIncOfButNFullAction:
    """Verify remove-all-inc-of-but-n-full action."""

    @patch("actions.helper")
    @patch("actions.hookenv")
    def test_remove_all_inc_of_but_n_full(self, mock_hookenv, mock_helper):
        """Verify remove-all-inc-of-but-n-full action."""
        result = "action_output".encode("utf-8")
        mock_helper.remove_all_inc_of_but_n_full.return_value = result
        expected_dict_input = dict(output=result.decode("utf-8"))
        actions.remove_all_inc_of_but_n_full()
        mock_helper.remove_all_inc_of_but_n_full.assert_called_once()
        mock_hookenv.action_set.called_with(expected_dict_input)
