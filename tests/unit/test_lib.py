#!/usr/bin/python3
import pytest

class TestLib():
    def test_pytest(self):
        assert True

    def test_duplicity_charm_config(self, duplicity):
        """ See if the helper fixture works to load charm configs """
        assert isinstance(duplicity.charm_config, dict)


    @pytest.mark.parametrize("backend,username,password,path,expected",
[("rsync", "user", "", "other.host:44/bak", "rsync://user@other.host:44/bak"),
 ("ssh", "user", "pass", "other.host:55/bak",
                                        "ssh://user:pass@other.host:55/bak"),
 ("scp", "", "", "other.host//bak", "scp://other.host//bak"),
 ("s3", "user", "pass", "s3://aws-remote-host/bak", "s3://aws-remote-host/bak"),
 pytest.param("ftp", "user", "pass", "ftp-host:bak",
                    "ftp://user:pass@ftp-host:bak", marks=pytest.mark.xfail),
])
    def test_duplicity_url(self, duplicity, backend, username, password, path,
                           expected):
        """ Test formation of duplicity urls for the various backend types """

        duplicity.charm_config["backend"] = backend
        duplicity.charm_config["remote_user"] = username
        duplicity.charm_config["remote_password"] = password
        duplicity.charm_config["remote_backup_url"] = path

        assert duplicity._backup_url() == expected + "/unit-mock-0"
