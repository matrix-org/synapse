from synapse.config.database import DatabaseConfig
from synapse.config.server import ServerConfig
from model import get_config_dir, get_data_dir, set_config_dir


def create_config(conf):
    server = ServerConfig().generate_config_section(
        conf["server_name"], get_data_dir(), False, conf["listeners"]
    )
    database = DatabaseConfig().generate_config_section(get_data_dir(), **conf)

    return "\n\n".join([server, database])


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
        }
    )
)

