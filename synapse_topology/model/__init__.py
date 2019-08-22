import yaml
import subprocess

from os.path import abspath, join

from synapse.config.homeserver import HomeServerConfig

from .constants import (
    BASE_CONFIG,
    CONFIG_LOCK,
    CONFIG_LOCK_DATA,
    DATA_SUBDIR,
    SERVER_NAME,
)
from .errors import BasConfigInUseError, BaseConfigNotFoundError, ConfigNotFoundError
from .config import create_config


def set_config_dir(conf_dir):
    global config_dir
    global data_dir
    config_dir = abspath(conf_dir)
    data_dir = abspath(join(config_dir, "./data"))


def get_config_dir():
    return config_dir


def get_data_dir():
    return data_dir


def get_config(sub_config=BASE_CONFIG):
    if sub_config:
        conf_path = join(config_dir, sub_config)
    try:
        with open(conf_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        raise BaseConfigNotFoundError() if sub_config == BASE_CONFIG else ConfigNotFoundError(
            sub_config
        )


def set_config(config):
    if config_in_use():
        raise BasConfigInUseError()

    for conf_name, conf in create_config(config).items():
        with open(abspath(join(get_config_dir, conf_name)), "w") as f:
            f.write(conf)


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
        join(config_dir, DATA_SUBDIR),
        server_name,
        generate_secrets=True,
        report_stats=report_stats,
    )

    with open(join(config_dir, BASE_CONFIG), "w") as f:
        f.write(conf)
        f.write(CONFIG_LOCK_DATA)


def get_server_name():
    config = get_config()
    if config:
        return config.get(SERVER_NAME)


def get_secret_key():
    config = get_config()
    server_name = config.get(SERVER_NAME)
    signing_key_path = join(config_dir, server_name + ".signing.key")
    subprocess.run(["generate_signing_key.py", "-o", signing_key_path])
    with open(signing_key_path, "r") as f:
        return f.read()


def verify_yaml():
    pass


def add_certs(cert, cert_key):
    with open(join(config_dir, get_server_name() + ".tls.crt"), "w") as cert_file, open(
        join(config_dir, get_server_name() + ".tls.key"), "w"
    ) as key_file:
        cert_file.write(cert)
        key_file.write(cert_key)
