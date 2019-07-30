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
