class ConfigNotFoundError(FileNotFoundError):
    def __init__(self, config_name):
        self.config_name = config_name

    def get_config_name(self):
        return self.config_name


class ServernameNotSetError(Exception):
    pass


class BaseConfigInUseError(Exception):
    pass
