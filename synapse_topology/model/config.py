from synapse.config.database import DatabaseConfig
from synapse.config.server import ServerConfig
from synapse.config.tls import TlsConfig
from synapse.config.logger import LoggingConfig
from synapse.config.homeserver import HomeServerConfig
from model import get_config_dir, get_data_dir, set_config_dir


def create_config(conf):
    server_name = conf["server_name"]
    del conf["server_name"]
    server = ServerConfig().generate_config_section(
        server_name, get_data_dir(), False, **conf
    )
    database = DatabaseConfig().generate_config_section(get_data_dir(), **conf)
    tls = TlsConfig().generate_config_section(
        get_config_dir(), server_name, get_data_dir(), **conf
    )
    basic_config = "\n\n".join([server, database, tls])

    unintialised_configs = list(HomeServerConfig.__bases__)
    for config in [ServerConfig, DatabaseConfig, TlsConfig]:
        unintialised_configs.remove(config)

    class Configs(*unintialised_configs):
        pass

    rest_of_config = Configs().generate_config(
        get_config_dir(),
        get_data_dir(),
        server_name,
        generate_secrets=True,
        report_stats=conf["report_stats"],
    )
    return basic_config, rest_of_config


set_config_dir("/exampledir/")
print(
    create_config(
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
)

