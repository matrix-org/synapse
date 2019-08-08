import os.path as path

import yaml

from synapse.config.homeserver import HomeServerConfig

from .constants import (
    BASE_CONFIG,
    CONFIG_LOCK,
    CONFIG_LOCK_DATA,
    DATA_SUBDIR,
    SECRET_KEY,
    SERVER_NAME,
)
from .errors import BasConfigInUseError, BaseConfigNotFoundError, ConfigNotFoundError


def set_config_dir(conf_dir):
    global config_dir
    config_dir = path.abspath(conf_dir)


def get_config(sub_config=BASE_CONFIG):
    if sub_config:
        conf_path = path.join(config_dir, sub_config)
    try:
        with open(conf_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        raise BaseConfigNotFoundError() if sub_config == BASE_CONFIG else ConfigNotFoundError(
            sub_config
        )


def get_config_dir():
    return config_dir


def set_config(config, sub_config=BASE_CONFIG):
    if sub_config == BASE_CONFIG and config_in_use():
        raise BasConfigInUseError()
    with open(path.join(config_dir, sub_config, "w")) as f:
        f.write(yaml.dump(config))


def config_in_use():
    """
    Checks if we set whether the config is in use. If it was set up by the system
    but synapse wasn't launched yet we will have set this to False. However if
    it's not present we assume someone else has set up synapse before so we assume
    the config is in use.
    """
    try:
        return get_config().get(CONFIG_LOCK, True)
    except FileNotFoundError:
        return False


def generate_base_config(server_name, report_stats):
    if config_in_use():
        raise BasConfigInUseError()

    print(config_dir)
    conf = HomeServerConfig().generate_config(
        config_dir,
        path.join(config_dir, DATA_SUBDIR),
        server_name,
        generate_secrets=True,
        report_stats=report_stats,
    )
    with open(path.join(config_dir, BASE_CONFIG), "w") as f:
        f.write(conf)
        f.write(CONFIG_LOCK_DATA)


def get_server_name():
    config = get_config()
    if config:
        return config.get(SERVER_NAME)


def get_secret_key():
    config = get_config()
    return config.get(SECRET_KEY)


def verify_yaml():
    pass


def add_certs(cert, cert_key):
    with open(
        path.join(config_dir, get_server_name() + ".tls.crt"), "w"
    ) as cert_file, open(
        path.join(config_dir, get_server_name() + ".tls.key"), "w"
    ) as key_file:
        cert_file.write(cert)
        key_file.write(cert_key)
