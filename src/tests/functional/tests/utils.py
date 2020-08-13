"""Zaza func tests utils."""
from collections import namedtuple
from functools import wraps

import zaza.model


def get_app_config(app_name):
    """Return app config."""
    return _convert_config(zaza.model.get_application_config(app_name))


def get_workload_application_status_checker(application_name, target_status):
    """Return a function for checking the status of all units of an application."""
    # inner function.
    async def checker():
        units = await zaza.model.async_get_units(application_name)
        unit_statuses_blocked = [
            unit.workload_status == target_status for unit in units
        ]
        return all(unit_statuses_blocked)

    return checker


def config_restore(*applications):
    """Return a function to reset application config."""

    def config_restore_wrap(f):
        AppConfigPair = namedtuple("AppConfigPair", ["app_name", "config"])

        @wraps(f)
        def wrapped_f(*args):
            original_configs = [
                AppConfigPair(app, get_app_config(app)) for app in applications
            ]
            try:
                f(*args)
            finally:
                for app_config_pair in original_configs:
                    zaza.model.set_application_config(
                        app_config_pair.app_name, app_config_pair.config
                    )
                zaza.model.block_until_all_units_idle(timeout=60)

        return wrapped_f

    return config_restore_wrap


def set_config_and_wait(application_name, config, model_name=None):
    """Set app config and wait for idle units."""
    zaza.model.set_application_config(
        application_name=application_name, configuration=config, model_name=model_name
    )
    zaza.model.block_until_all_units_idle()


def _convert_config(config):
    """Convert config dictionary from get_config to one valid for set_config."""
    clean_config = dict()
    for key, value in config.items():
        clean_config[key] = "{}".format(value["value"])
    return clean_config
