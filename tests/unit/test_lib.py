#!/usr/bin/python3


class TestLib():
    def test_pytest(self):
        assert True

    def test_duplicity(self, duplicity):
        """ See if the helper fixture works to load charm configs """
        assert isinstance(duplicity.charm_config, dict)

    # Include tests for functions in lib_duplicity
