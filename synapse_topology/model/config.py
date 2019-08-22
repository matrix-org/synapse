from synapse.config.database import DatabaseConfig
from synapse.config.server import ServerConfig
from synapse.config.tls import TlsConfig
from synapse.config.logger import LoggingConfig
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
    return "\n\n".join([server, database, tls])


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
        }
    )
)

