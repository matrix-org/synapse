from synapse.config.database import DatabaseConfig
from synapse.config.server import ServerConfig
from synapse.config.tls import TlsConfig
from synapse.config.logger import LoggingConfig
from synapse.config.homeserver import HomeServerConfig
from model import get_config_dir, get_data_dir, set_config_dir


def create_config(conf):
    server_name = conf["server_name"]
    del conf["server_name"]

    config_dir_path = get_config_dir()
    data_dir_path = get_data_dir()

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

    return {"homeserver.yaml": base_config, "the_rest.yaml": rest_of_config}


set_config_dir("/exampledir/")
confs = create_config(
    {
        "server_name": "banterserver",
        "database": "sqlcrap",
        "listeners": [
            {
                "port": 8448,
                "resources": [{"names": ["federation"]}],
                "tls": True,
                "type": "http",
            },
            {
                "port": 443,
                "resources": [{"names": ["client"]}],
                "tls": False,
                "type": "http",
            },
        ],
        "tls_certificate_path": "asdfasfdasdfadf",
        "tls_private_key_path": "asdfasfdha;kdfjhafd",
        "acme_domain": "asdfaklhsadfkj",
        "report_stats": True,
    }
)
for conf_name, conf in confs.items():
    with open(conf_name, "w") as f:
        f.write(conf)
