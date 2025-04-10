"""Zaza fun tests."""

import asyncio
import base64
import concurrent.futures
import unittest

import zaza.model
from tests.configure import ubuntu_backup_directory_source, ubuntu_user_pass

from tests import utils


def _run(coro):
    """Return result of an async function."""
    return asyncio.get_event_loop().run_until_complete(coro)


class BaseDuplicityTest(unittest.TestCase):
    """Base class for Duplicity charm tests."""

    @classmethod
    def setUpClass(cls):
        """Run setup for Duplicity tests."""
        cls.model_name = zaza.model.get_juju_model()
        cls.application_name = "duplicity"


class DuplicityBackupCronTest(BaseDuplicityTest):
    """Base class for Duplicity Backup cron job charm tests."""

    @classmethod
    def setUpClass(cls):
        """Run setup for Duplicity Backup cron job charm tests."""
        super().setUpClass()

    @utils.config_restore("duplicity")
    def test_cron_creation(self):
        """Verify cron job creation."""
        options = ["daily", "weekly", "monthly"]
        for option in options:
            new_config = {"backup_frequency": option}
            zaza.model.set_application_config(self.application_name, new_config)
            try:
                zaza.model.block_until_file_has_contents(
                    application_name=self.application_name,
                    remote_file="/etc/cron.d/periodic_backup",
                    expected_contents=option,
                    timeout=60,
                )
            except concurrent.futures._base.TimeoutError:
                self.fail(
                    "Cron file /etc/cron.d/period_backup never populated with "
                    "option <{}>".format(option)
                )

    @utils.config_restore("duplicity")
    def test_cron_creation_cron_string(self):
        """Verify cron job creation."""
        cron_string = "* * * * *"
        new_config = {"backup_frequency": cron_string}
        zaza.model.set_application_config(self.application_name, new_config)
        try:
            zaza.model.block_until_file_has_contents(
                application_name=self.application_name,
                remote_file="/etc/cron.d/periodic_backup",
                expected_contents=cron_string,
                timeout=60,
            )
        except concurrent.futures._base.TimeoutError:
            self.fail(
                "Cron file /etc/cron.d/period_backup never populated with "
                "option <{}>".format(cron_string)
            )

    @utils.config_restore("duplicity")
    def test_cron_invalid_cron_string(self):
        """Verify cron job creation with invalid frequency."""
        cron_string = "* * * *"
        new_config = {"backup_frequency": cron_string}
        zaza.model.set_application_config(self.application_name, new_config)
        try:
            duplicity_workload_checker = utils.get_workload_application_status_checker(
                self.application_name, "blocked"
            )
            _run(zaza.model.async_block_until(duplicity_workload_checker, timeout=15))
            a_unit = zaza.model.get_units(self.application_name)[0]
            self.assertEqual(
                a_unit.workload_status_message,
                'Invalid value "{}" for "backup_frequency"'.format(cron_string),
            )
        except concurrent.futures._base.TimeoutError:
            self.fail("Failed to enter blocked state with invalid backup_frequency.")

    @utils.config_restore("duplicity")
    def test_no_cron(self):
        """Verify manual or invalid cron job frequency."""
        options = ["manual"]
        for option in options:
            new_config = {"backup_frequency": option}
            zaza.model.set_application_config(self.application_name, new_config)
            try:
                zaza.model.block_until_file_missing(
                    model_name=self.model_name,
                    app=self.application_name,
                    path="/etc/cron.d/periodic_backup",
                    timeout=60,
                )
            except concurrent.futures._base.TimeoutError:
                self.fail(
                    "Cron file /etc/cron.d/period_backup exists with " "option <{}>".format(option)
                )


class DuplicityDeletionCronTest(BaseDuplicityTest):
    """Base class for Duplicity Backup cron job charm tests."""

    @classmethod
    def setUpClass(cls):
        """Run setup for Duplicity Backup cron job charm tests."""
        super().setUpClass()

    @utils.config_restore("duplicity")
    def test_deletion_cron_creation(self):
        """Verify deletion cron job creation."""
        options = {"30d": "0 23 * * *", "12h": "40 * * * *"}
        for retention, frequency in options.items():
            new_config = {
                "retention_period": retention,
                "deletion_frequency": frequency,
            }
            zaza.model.set_application_config(self.application_name, new_config)
            try:
                zaza.model.block_until_file_has_contents(
                    application_name=self.application_name,
                    remote_file="/etc/cron.d/periodic_deletion",
                    expected_contents=frequency,
                    timeout=60,
                )
            except concurrent.futures._base.TimeoutError:
                self.fail(
                    "Cron file /etc/cron.d/period_deletion never populated with "
                    "option <{}>".format(frequency)
                )

    @utils.config_restore("duplicity")
    def test_deletion_cron_invalid_retention(self):
        """Verify deletion cron job creation with invalid retention."""
        rp = "x"
        new_config = {"retention_period": rp, "deletion_frequency": "daily"}
        utils.set_config_and_wait(self.application_name, new_config, delay=5)
        try:
            duplicity_workload_checker = utils.get_workload_application_status_checker(
                self.application_name, "blocked"
            )
            _run(zaza.model.async_block_until(duplicity_workload_checker, timeout=15))
            a_unit = zaza.model.get_units(self.application_name)[0]
            self.assertEqual(
                a_unit.workload_status_message,
                'Invalid value "{}" for "retention_period"'.format(rp),
            )
        except concurrent.futures._base.TimeoutError:
            self.fail("Failed to enter blocked state with invalid retention_period.")

    @utils.config_restore("duplicity")
    def test_deletion_cron_invalid_frequency(self):
        """Verify deletion cron job creation with invalid frequency."""
        cron_string = "* * * *"
        new_config = {"retention_period": "30d", "deletion_frequency": cron_string}
        zaza.model.set_application_config(self.application_name, new_config)
        try:
            duplicity_workload_checker = utils.get_workload_application_status_checker(
                self.application_name, "blocked"
            )
            _run(zaza.model.async_block_until(duplicity_workload_checker, timeout=15))
            a_unit = zaza.model.get_units(self.application_name)[0]
            self.assertEqual(
                a_unit.workload_status_message,
                'Invalid value "{}" for "deletion_frequency"'.format(cron_string),
            )
        except concurrent.futures._base.TimeoutError:
            self.fail("Failed to enter blocked state with invalid deletion_frequency.")

    @utils.config_restore("duplicity")
    def test_no_deletion_cron(self):
        """Verify deletion cron removal via manual retention trigger."""
        new_config = {"retention_period": "30d", "deletion_frequency": "0 23 * * *"}
        zaza.model.set_application_config(self.application_name, new_config)
        try:
            zaza.model.block_until_file_has_contents(
                application_name=self.application_name,
                remote_file="/etc/cron.d/periodic_deletion",
                expected_contents="0 23 * * *",
                timeout=60,
            )
        except concurrent.futures._base.TimeoutError:
            self.fail("Cron file /etc/cron.d/period_deletion never populated correctly")
        new_config["retention_period"] = "manual"
        zaza.model.set_application_config(self.application_name, new_config)
        try:
            zaza.model.block_until_file_missing(
                model_name=self.model_name,
                app=self.application_name,
                path="/etc/cron.d/periodic_deletion",
                timeout=60,
            )
        except concurrent.futures._base.TimeoutError:
            self.fail("Cron file /etc/cron.d/periodic_deletion exists")


class DuplicityEncryptionValidationTest(BaseDuplicityTest):
    """Verify encryption validation."""

    @classmethod
    def setUpClass(cls):
        """Set up encryption validation tests."""
        super().setUpClass()

    @utils.config_restore("duplicity")
    def test_encryption_true_no_key_no_passphrase_blocks(self):
        """Verify unit is blocked with no passphrase or key."""
        new_config = {
            "encryption_passphrase": "",
            "gpg_public_key": "",
            "disable_encryption": "False",
        }
        zaza.model.set_application_config(self.application_name, new_config, self.model_name)
        try:
            duplicity_workload_checker = utils.get_workload_application_status_checker(
                self.application_name, "blocked"
            )
            _run(zaza.model.async_block_until(duplicity_workload_checker, timeout=15))
            a_unit = zaza.model.get_units(self.application_name)[0]
            self.assertEqual(
                a_unit.workload_status_message,
                "Must set either an encryption passphrase, GPG public key, "
                "or disable encryption",
            )
        except concurrent.futures._base.TimeoutError:
            self.fail(
                "Failed to enter blocked state with encryption enables and "
                "no passphrase or key."
            )

    @utils.config_restore("duplicity")
    def test_encryption_true_with_key(self):
        """Verify encryption with a valid gpg key."""
        zaza.model.set_application_config(
            self.application_name, {"disable_encryption": "False"}, self.model_name
        )
        try:
            duplicity_workload_checker = utils.get_workload_application_status_checker(
                self.application_name, "blocked"
            )
            _run(zaza.model.async_block_until(duplicity_workload_checker, timeout=15))
        except concurrent.futures._base.TimeoutError:
            self.fail(
                "Failed to enter blocked state with encryption enables and "
                "no passphrase or key."
            )
        zaza.model.set_application_config(self.application_name, {"gpg_public_key": "S0M3k3Y"})
        try:
            zaza.model.block_until_all_units_idle()
        except concurrent.futures._base.TimeoutError:
            self.fail(
                "Not all units entered idle state. Config change back failed "
                "to achieve active/idle."
            )

    @utils.config_restore("duplicity")
    def test_encryption_true_with_passphrase(self):
        """Verify encryption with a valid passphrase."""
        zaza.model.set_application_config(
            self.application_name, {"disable_encryption": "False"}, self.model_name
        )
        try:
            duplicity_workload_checker = utils.get_workload_application_status_checker(
                self.application_name, "blocked"
            )
            _run(zaza.model.async_block_until(duplicity_workload_checker, timeout=15))
        except concurrent.futures._base.TimeoutError:
            self.fail(
                "Failed to enter blocked state with encryption enables and "
                "no passphrase or key."
            )
        zaza.model.set_application_config(
            self.application_name, {"encryption_passphrase": "somephrase"}
        )
        try:
            zaza.model.block_until_all_units_idle()
        except concurrent.futures._base.TimeoutError:
            self.fail(
                "Not all units entered idle state. Config change back "
                "failed to achieve active/idle."
            )


class BaseDuplicityCommandTest(BaseDuplicityTest):
    """VHelper class to use for duplicity command tests."""

    @classmethod
    def setUpClass(cls):
        """Set up do-backup command tests."""
        super().setUpClass()
        cls.backup_host = zaza.model.get_units("backup-host")[0]
        cls.duplicity_unit = zaza.model.get_units("duplicity")[0].name
        user_pass_pair = ubuntu_user_pass.split(":")
        cls.ssh_priv_key = cls.get_ssh_priv_key()
        cls.base_config = {
            "remote_backup_url": cls.backup_host.public_address,
            "aux_backup_directory": ubuntu_backup_directory_source,
            "remote_user": user_pass_pair[0],
            "remote_password": user_pass_pair[1],
        }
        cls.auxiliary_actions = []
        cls.action_params = None

    @staticmethod
    def get_ssh_priv_key():
        """Return ssh private key."""
        with open("./tests/resources/testing_id_rsa", "rb") as f:
            ssh_private_key = f.read()
        encoded_ssh_private_key = base64.b64encode(ssh_private_key)
        return encoded_ssh_private_key.decode("utf-8")

    def _run(self, **config):
        """Run action on zaza model."""
        config.update(self.base_config)
        utils.set_config_and_wait(self.application_name, config)
        for a in self.auxiliary_actions:
            zaza.model.run_action(self.duplicity_unit, a, raise_on_failure=True)
        zaza.model.run_action(
            self.duplicity_unit,
            self.action,
            action_params=self.action_params,
            raise_on_failure=True,
        )


class DuplicityBackupCommandTest(BaseDuplicityCommandTest):
    """Verify do-backup command."""

    @classmethod
    def setUpClass(cls):
        """Set up do-backup command tests."""
        super().setUpClass()
        cls.action = "do-backup"

    @utils.config_restore("duplicity")
    def test_scp_full(self):
        """Verify do-backup action with scp."""
        additional_config = {"backend": "scp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_file_full(self):
        """Verify do-backup action with file."""
        additional_config = {
            "backend": "file",
            "remote_backup_url": "/home/ubuntu/test-backups",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_scp_full_ssh_key(self):
        """Verify do-backup action with scp and private key."""
        additional_config = {
            "backend": "scp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_rsync_full_ssh_key(self):
        """Verify do-backup action with rsync and private key."""
        additional_config = {
            "backend": "rsync",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full(self):
        """Verify do-backup action with sftp and password."""
        additional_config = {"backend": "sftp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full_ssh_key(self):
        """Verify do-backup action with sftp and private key."""
        additional_config = {
            "backend": "sftp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_ftp_full(self):
        """Verify do-backup action with ftp and password."""
        additional_config = {"backend": "ftp"}
        self._run(**additional_config)


class DuplicityListFilesCommandTest(BaseDuplicityCommandTest):
    """Verify list-current-files command."""

    @classmethod
    def setUpClass(cls):
        """Set up list-current-files command tests."""
        super().setUpClass()
        cls.action = "list-current-files"
        cls.auxiliary_actions = ["do-backup"]

    @utils.config_restore("duplicity")
    def test_scp_full_list_current_files(self):
        """Verify list-current-files action with scp."""
        additional_config = {"backend": "scp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_file_full_list_current_files(self):
        """Verify list-current-files action with file."""
        additional_config = {
            "backend": "file",
            "remote_backup_url": "/home/ubuntu/test-backups",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_scp_full_ssh_key_list_current_files(self):
        """Verify list-current-files action with scp and private key."""
        additional_config = {
            "backend": "scp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_rsync_full_ssh_key_list_current_files(self):
        """Verify list-current-files action with rsync and private key."""
        additional_config = {
            "backend": "rsync",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full_list_current_files(self):
        """Verify list-current-files action with sftp and password."""
        additional_config = {"backend": "sftp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full_ssh_key_list_current_files(self):
        """Verify list-current-files action with sftp and private key."""
        additional_config = {
            "backend": "sftp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_ftp_full_list_current_files(self):
        """Verify list-current-files action with ftp and password."""
        additional_config = {"backend": "ftp"}
        self._run(**additional_config)


class DuplicityRemoveOlderThanCommandTest(BaseDuplicityCommandTest):
    """Verify remove-older-than command."""

    @classmethod
    def setUpClass(cls):
        """Set up remove-older-than command tests."""
        super().setUpClass()
        cls.action = "remove-older-than"
        cls.auxiliary_actions = ["do-backup", "do-backup"]
        cls.action_params = {"time": "now"}

    @utils.config_restore("duplicity")
    def test_scp_full_list_remove_older_than(self):
        """Verify remove-older-than action with scp."""
        additional_config = {"backend": "scp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_file_full_remove_older_than(self):
        """Verify remove-older-than action with file."""
        additional_config = {
            "backend": "file",
            "remote_backup_url": "/home/ubuntu/test-backups",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_scp_full_ssh_key_remove_older_than(self):
        """Verify remove-older-than action with scp and private key."""
        additional_config = {
            "backend": "scp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_rsync_full_ssh_key_remove_older_than(self):
        """Verify remove-older-than action with rsync and private key."""
        additional_config = {
            "backend": "rsync",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full_remove_older_than(self):
        """Verify remove-older-than action with sftp and password."""
        additional_config = {"backend": "sftp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full_ssh_key_remove_older_than(self):
        """Verify remove-older-than action with sftp and private key."""
        additional_config = {
            "backend": "sftp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_ftp_full_remove_older_than(self):
        """Verify remove-older-than action with ftp and password."""
        additional_config = {"backend": "ftp"}
        self._run(**additional_config)


class DuplicityRemoveAllButNFullCommandTest(BaseDuplicityCommandTest):
    """Verify remove-all-but-n-full command."""

    @classmethod
    def setUpClass(cls):
        """Set up remove-all-but-n-full command tests."""
        super().setUpClass()
        cls.action = "remove-all-but-n-full"
        cls.auxiliary_actions = ["do-backup", "do-backup"]
        cls.action_params = {"count": 1}

    @utils.config_restore("duplicity")
    def test_scp_full_list_remove_all_but_n_full(self):
        """Verify remove-all-but-n-full action with scp."""
        additional_config = {"backend": "scp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_file_full_remove_all_but_n_full(self):
        """Verify remove-all-but-n-full action with file."""
        additional_config = {
            "backend": "file",
            "remote_backup_url": "/home/ubuntu/test-backups",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_scp_full_ssh_key_remove_all_but_n_full(self):
        """Verify remove-all-but-n-full action with scp and private key."""
        additional_config = {
            "backend": "scp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_rsync_full_ssh_key_remove_all_but_n_full(self):
        """Verify remove-all-but-n-full action with rsync and private key."""
        additional_config = {
            "backend": "rsync",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full_remove_all_but_n_full(self):
        """Verify remove-all-but-n-full action with sftp and password."""
        additional_config = {"backend": "sftp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full_ssh_key_remove_all_but_n_full(self):
        """Verify remove-all-but-n-full action with sftp and private key."""
        additional_config = {
            "backend": "sftp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_ftp_full_remove_all_but_n_full(self):
        """Verify remove-all-but-n-full action with ftp and password."""
        additional_config = {"backend": "ftp"}
        self._run(**additional_config)


class DuplicityRemoveAllIncOfButNFullCommandTest(BaseDuplicityCommandTest):
    """Verify remove-all-inc-of-but-n-fullcommand."""

    @classmethod
    def setUpClass(cls):
        """Set up remove-all-inc-of-but-n-full command tests."""
        super().setUpClass()
        cls.action = "remove-all-inc-of-but-n-full"
        cls.auxiliary_actions = ["do-backup", "do-backup"]
        cls.action_params = {"count": 1}

    @utils.config_restore("duplicity")
    def test_scp_full_list_remove_all_inc_of_but_n_full(self):
        """Verify remove-all-inc-of-but-n-full action with scp."""
        additional_config = {"backend": "scp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_file_full_remove_all_inc_of_but_n_full(self):
        """Verify remove-all-inc-of-but-n-full action with file."""
        additional_config = {
            "backend": "file",
            "remote_backup_url": "/home/ubuntu/test-backups",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_scp_full_ssh_key_remove_all_inc_of_but_n_full(self):
        """Verify remove-all-inc-of-but-n-full action with scp and private key."""
        additional_config = {
            "backend": "scp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_rsync_full_ssh_key_remove_all_inc_of_but_n_full(self):
        """Verify remove-all-inc-of-but-n-full action with rsync and private key."""
        additional_config = {
            "backend": "rsync",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full_remove_all_inc_of_but_n_full(self):
        """Verify remove-all-inc-of-but-n-full action with sftp and password."""
        additional_config = {"backend": "sftp"}
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_sftp_full_ssh_remove_all_inc_of_but_n_full(self):
        """Verify remove-all-inc-of-but-n-full action with sftp and private key."""
        additional_config = {
            "backend": "sftp",
            "private_ssh_key": self.ssh_priv_key,
            "remote_password": "",
        }
        self._run(**additional_config)

    @utils.config_restore("duplicity")
    def test_ftp_full_remove_all_inc_of_but_n_full(self):
        """Verify remove-all-inc-of-but-n-full action with ftp and password."""
        additional_config = {"backend": "ftp"}
        self._run(**additional_config)
