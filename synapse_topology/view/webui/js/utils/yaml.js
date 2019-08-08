import yaml from 'yaml';
import { TLS_TYPES, REVERSE_PROXY_TYPES } from '../actions/constants';
import { CONFIG_LOCK } from '../api/constants';

const listeners = config => {
  const listeners = [];
  if (config.tls == TLS_TYPES.TLS) {
    listeners.push({
      port: config.synapse_federation_port,
      tls: true,
      bind_addresses: ['::1', '127.0.0.1'],
      type: "http",
      x_forwarded: true,

      resources: [{
        names: ["federation"],
        compress: false,
      }],
    });
  } else {
    listeners.push({
      port: config.synapse_federation_port,
      tls: true,
      type: "http",

      resources: [{
        names: ["federation"],
      }],
    });
  }

  if (config.synapse_client_port == config.synapse_federation_port) {
    listeners[0].resources[0].names.push("client");
  } else if (config.tls == TLS_TYPES.TLS) {
    listeners.push({
      port: config.synapse_client_port,
      tls: true,
      bind_addresses: ['::1', '127.0.0.1'],
      type: "http",
      x_forwarded: true,

      resources: [{
        names: ["client"],
        compress: false,
      }],
    });
  } else {
    listeners.push({
      port: config.synapse_client_port,
      tls: true,
      type: "http",

      resources: [{
        names: ["client"],
      }],
    });
  }
  return { listeners: listeners };
}

const tls_paths = config => {
  if (config.reverse_proxy == REVERSE_PROXY_TYPES.TLS) {
    return {
      tls_certificate_path: config.tls_cert_path,
      tls_private_key_path: config.tls_cert_key_path,
    }
  } else if (config.reverser_proxy == REVERSE_PROXY_TYPES.ACME) {
    return {
      tls_certificate_path: config.config_dir + "/" + config.server_name + ".tls.cert",
      tls_private_key_path: config.config_dir + "/" + config.server_name + ".tls.key",
    }
  } else {
    return {}
  }
}

const acme = config => {
  if (config.tls == TLS_TYPES.ACME) {
    return {
      acme: {
        url: "https://acme-v01.api.letsencrypt.org/directory",
        port: 80,
        bind_addresses: ['::', '0.0.0.0'],
        reprovision_threshold: 30,
        domain: config.delegation_server_name ? config.delegation_server_name : servername,
        account_key_file: config.config_dir + "/data/acme_account.key",
      }
    }
  } else {
    return {}
  }
}

const database = config => ({
  database: {
    name: config.database,
    args: config.config_dir + "/data/homeserver.db"
  }
})

export const base_config_to_synapse_config = config => {
  const conf = {
    server_name: config.servername,
    report_stats: config.report_stats,
    log_config: config.config_dir + "/" + config.server_name + ".log.config",
    media_store_path: config.config_dir + "/data/media_store",
    uploads_path: config.config_dir + "/data/uploads",
    pid_file: config.config_dir + "/data/homeserver.pid",
    ...listeners(config),
    ...tls_paths(config),
    ...acme(config),
    ...database(config),
    [CONFIG_LOCK]: true,
  }
  console.log(conf)
  return conf
}
