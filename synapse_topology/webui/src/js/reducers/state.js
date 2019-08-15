const state = {
  setup_ui: {
    active_blocks: ["block1"],
  },
  config_ui: {

  },
  base_config: {
    setup_done: true,
    base_config_checked: false,
    servername: "server_name",
    report_stats: false,
    getting_secret_key: false,
    secret_key: "asdfsadf",
    delegation_type: "local|well_known|DNS_SRV",
    delegation_server_name: "name",
    delegation_federation_port: "\"\"|325",
    delegation_client_port: "\"\"|325",
    reverse_proxy: "nginx|caddy|apache|haproxy|other|none",
    tls: "acme|tls|reverseproxy",
    testing_cert_paths: true,
    uploading_certs: true,
    cert_path_invalid: true,
    cert_key_path_invalid: true,
    tls_cert_path: "sadfaf",
    tls_cert_key_path: "sdfasdf",
    tls_cert_file: "sadfa;dlf;sad;fkla;sdlfjkas;dlfkjas;dflkja;sdfkljadf ------",
    tls_cert_key_file: "sadfa;dlf;sad;fkla;sdlfjkas;dlfkjas;dflkja;sdfkljadf ------",
    tls_path: "sdasfaf/a/fdasfd/a/fasd/",
    verifying_ports: true,
    synapse_federation_port_free: true,
    synapse_client_port_free: true,
    synapse_federation_port: 1234,
    synapse_client_port: 1234,
    database: "sqlite3|postgres",
    config_dir: "sadfasdf",
  }
}