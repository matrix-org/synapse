SERVERNAME_SCHEMA = {
    "type": "object",
    "properties": {
        "server_name": {"type": "string", "minlength": 1},
        "report_stats": {"type": "boolean"},
    },
    "required": ["server_name", "report_stats"],
}

BASE_CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "server_name": {"type": "string", "minlength": 1},
        "report_stats": {"type": "boolean"},
    },
    "required": ["server_name", "report_stats"],
}

CERT_PATHS_SCHEMA = {
    "type": "object",
    "properties": {
        "cert_path": {"type": "string", "minlength": 1},
        "cert_key_path": {"type": "string", "minlength": 1},
    },
    "required": ["cert_path", "cert_key_path"],
}

CERTS_SCHEMA = {
    "type": "object",
    "properties": {
        "cert": {"type": "string", "minlength": 1},
        "cert_key": {"type": "string", "minlength": 1},
    },
    "required": ["cert", "cert_key"],
}
