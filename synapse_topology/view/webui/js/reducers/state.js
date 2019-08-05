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
    reverse_proxy: "nginx|caddy|apache|haproxy|other|none",
    tls: "acme|tls|none|reverseproxy",
    testing_cert_paths: true,
    uploading_certs: true,
    cert_path_invalid: true,
    cert_key_path_invalid: true,
    tls_cert_path: "sadfaf",
    tls_cert_key_path: "sdfasdf",
    tls_cert_file: "sadfa;dlf;sad;fkla;sdlfjkas;dlfkjas;dflkja;sdfkljadf ------",
    tls_cert_key_file: "sadfa;dlf;sad;fkla;sdlfjkas;dlfkjas;dflkja;sdfkljadf ------",
    tls_path: "sdasfaf/a/fdasfd/a/fasd/",
  }
}