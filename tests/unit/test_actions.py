import imp

import mock


class TestActions():
    def test_rdiff_archive(self, duplicity, monkeypatch):
        mock_function = mock.Mock()
        monkeypatch.setattr(duplicity, 'rdiff_archive', mock_function)
        assert mock_function.call_count == 0
        imp.load_source('rdiff_archive', './actions/rdiff_archive')
        assert mock_function.call_count == 1

    def test_show_history(self, duplicity, monkeypatch):
        mock_function = mock.Mock()
        monkeypatch.setattr(duplicity, 'show_history', mock_function)
        assert mock_function.call_count == 0
        imp.load_source('show_history', './actions/show_history')
        assert mock_function.call_count == 1