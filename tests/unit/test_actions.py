import imp

import mock


class TestActions():
    def test_show_history(self, duplicity, monkeypatch):
        mock_function = mock.Mock()
        monkeypatch.setattr(duplicity, 'show_history', mock_function)
        assert mock_function.call_count == 0
        imp.load_source('show-history', './actions/show-history')
        assert mock_function.call_count == 1

    def test_do_backup(self, duplicity, monkeypatch):
        mock_function = mock.Mock()
        monkeypatch.setattr(duplicity, 'do_backup', mock_function)
        assert mock_function.call_count == 0
        imp.load_source('do_backup', './actions/do-backup')
        assert mock_function.call_count == 1