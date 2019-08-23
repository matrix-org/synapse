import yaml
import subprocess

from os.path import abspath, join, exists, isdir

from synapse.config.homeserver import HomeServerConfig

from .constants import (
    BASE_CONFIG,
    CONFIG_LOCK,
    CONFIG_LOCK_DATA,
    DATA_SUBDIR,
    SERVER_NAME,
)
from .errors import BaseConfigInUseError, ConfigNotFoundError, ServernameNotSetError
from .config import create_config
from .util import is_subpath

from synapse.config import find_config_files, read_config_files


class Model:
    """
    The Model brokers modification of the config file and signing keys in the config
    directory.
    """

    def __init__(self, config_dir):
        self.config_dir = abspath(config_dir)
        self.data_dir = abspath(join(self.config_dir, DATA_SUBDIR))
        if not isdir(self.config_dir) or not isdir(self.data_dir):
            raise FileNotFoundError()

    def get_config(self, config_path):
        """
        Retrieves a config from the config directory. Any path can be provided
        but it must be a subdirectory of self.config_dir

        Args:
            config_path (str): path to the config

        Returns:
            dict: the yaml parse of the config file
        """
        conf_path = abspath(join(self.config_dir, config_path))

        if not is_subpath(config_dir, conf_path):
            raise FileNotFoundError()

        with open(conf_path, "r") as f:
            return yaml.safe_load(f)

    def write_config(self, config):
        """
        Given a config generates a templated config from synapse and writes it
        out to the config dir. It will raise an exception if the config in
        the config directory is in use.

        Args:
            config (dict): The configuration to template out.
        """
        if self.config_in_use():
            raise BaseConfigInUseError()

        for conf_name, conf in create_config(
            self.config_dir, self.data_dir, config
        ).items():
            with open(abspath(join(self.config_dir, conf_name)), "w") as f:
                f.write(conf)

    def config_in_use(self):
        """
        Checks if we set whether the config is in use. If it was set up by the system
        but synapse wasn't launched yet we will have set this to False. However if
        it's not present we assume someone else has set up synapse before so we assume
        the config is in use.
        """
        try:
            return read_config_files(find_config_files(self.config_dir)).get(
                CONFIG_LOCK, True
            )
        except FileNotFoundError:
            return False

    def generate_secret_key(self, server_name):
        if self.config_in_use():
            raise BaseConfigInUseError()

        signing_key_path = join(self.config_dir, server_name + ".signing.key")
        subprocess.run(["generate_signing_key.py", "-o", signing_key_path])
        with open(signing_key_path, "r") as f:
            return f.read()
