from synapse.config.database import DatabaseConfig
from synapse.config.server import ServerConfig
from synapse.config.tls import TlsConfig
from synapse.config.logger import LoggingConfig
from synapse.config.homeserver import HomeServerConfig


def create_config(config_dir_path, data_dir_path, conf):
    server_name = conf["server_name"]
    del conf["server_name"]

    server_config_in_use = conf["server_config_in_use"]
    del conf["server_config_in_use"]

    base_configs = [ServerConfig, DatabaseConfig, TlsConfig]

    # Generate configs for all the ones we didn't cover explicitely
    uninitialized_configs = [
        x for x in list(HomeServerConfig.__bases__) if x not in base_configs
    ]

    class BaseConfig(*base_configs):
        pass

    class Configs(*uninitialized_configs):
        pass

    config_args = {
        "config_dir_path": config_dir_path,
        "data_dir_path": data_dir_path,
        "server_name": server_name,
        **conf,
    }

    base_config = BaseConfig().generate_config(**config_args)

    rest_of_config = Configs().generate_config(**config_args)

    return {
        "homeserver.yaml": base_config
        + "\n\nserver_config_in_use: {}".format(server_config_in_use),
        "the_rest.yaml": rest_of_config,
    }

