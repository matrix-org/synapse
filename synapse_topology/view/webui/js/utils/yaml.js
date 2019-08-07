import yaml from 'yaml';
import { TLS_TYPES } from '../actions/constants';

const listeners = conf => {
  const listeners = [];
  if (conf.tls == TLS_TYPES.TLS) {
    listeners.append({
      port: conf.synapse_federation_port,
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
    listeners.append({
      port: conf.synapse_federation_port,
      tls: true,
      type: "http",

      resources: [{
        names: ["federation"],
      }],
    });
  }

  if (conf.synapse_client_port == conf.synapse_federation_port) {
    listeners[0].resources[0].names.append("client");
  } else if (conf.tls == TLS_TYPES.TLS) {
    listeners.append({
      port: conf.synapse_client_port,
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
    listeners.append({
      port: conf.synapse_client_port,
      tls: true,
      type: "http",

      resources: [{
        names: ["client"],
      }],
    });
  }
  return listeners;
}

const base_config_to_yaml = conf => ({
  server_name: conf.servername,
  listeners: listeners(conf),

})