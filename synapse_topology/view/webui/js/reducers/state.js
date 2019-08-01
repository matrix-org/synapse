const state = {
  ui: {
    base_config_done: true,
    active_ui
  },
  base_config: {
    servername: "server_name",
    report_stats: false,
    getting_secret_key: false,
    secret_key: "asdfsadf",
    delegation_type: "local|well_known|DNS_SRV",
    delegation_server_name: "name",
    reverse_proxy: "nginx|caddy|apache|haproxy|other|none"
  }
}