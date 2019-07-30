from .constants import BASE_CONFIG


class ConfigNotFoundError(FileNotFoundError):
    def __init__(self, config_name):
        self.config_name = config_name

    def get_config_name(self):
        return self.config_name


class BaseConfigNotFoundError(ConfigNotFoundError):
    def __init__(self):
        super().__init__(BASE_CONFIG)


class BasConfigInUseError(Exception):
    pass
