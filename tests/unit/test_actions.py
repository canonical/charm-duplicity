import imp

import mock


class TestActions():
    def test_show_history(self, duplicity, monkeypatch):
        mock_function = mock.Mock()
        monkeypatch.setattr(duplicity, 'show_history', mock_function)
        assert mock_function.call_count == 0
        imp.load_source('show_history', './actions/show_history')
        assert mock_function.call_count == 1