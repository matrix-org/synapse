import {
  SET_SERVERNAME,
  SET_STATS,
  SET_SECRET_KEY,
  GETTING_SECRET_KEY,
  SET_DELEGATION,
  SET_DELEGATION_SERVERNAME,
  SET_REVERSE_PROXY,
  SET_TLS,
  TESTING_TLS_CERT_PATHS,
  SET_TLS_CERT_PATHS,
  SET_TLS_CERT_PATHS_VALIDITY,
  SET_TLS_CERT_FILES,
  UPLOADING_TLS_CERT_PATHS,
  TESTING_SYNAPSE_PORTS,
  SET_SYNAPSE_PORTS,
  SET_SYNAPSE_PORTS_FREE,
  SET_DATABASE,
} from "../actions/types";

export default (state = { servername: undefined }, action) => {
  switch (action.type) {
    case SET_SERVERNAME:
      return {
        ...state,
        servername: action.servername,
      }
    case SET_STATS:
      return {
        ...state,
        report_stats: action.consent,
      }
    case GETTING_SECRET_KEY:
      return {
        ...state,
        secret_key_loaded: false,
      }
    case SET_SECRET_KEY:
      return {
        ...state,
        secret_key_loaded: true,
        secret_key: action.key,
      };
    case SET_DELEGATION:
      return {
        ...state,
        delegation_type: action.delegation_type,
      }
    case SET_DELEGATION_SERVERNAME:
      return {
        ...state,
        delegation_servername: action.servername,
      }
    case SET_DELEGATION_SERVERNAME:
      return {
        ...state,
        delegation_federation_port: action.federation_port,
        delegation_client_port: action.client_port,
      }
    case SET_REVERSE_PROXY:
      return {
        ...state,
        reverse_proxy: action.proxy_type,
      }
    case SET_TLS:
      return {
        ...state,
        tls: action.tls_type,
      }
    case TESTING_TLS_CERT_PATHS:
      return {
        ...state,
        testing_cert_paths: action.testing,
      }
    case SET_TLS_CERT_PATHS_VALIDITY:
      return {
        ...state,
        cert_path_invalid: action.cert_path_invalid,
        cert_key_path_invalid: action.cert_key_path_invalid,
      }
    case SET_TLS_CERT_PATHS:
      return {
        ...state,
        tls_cert_path: action.cert_path,
        tls_cert_key_path: action.cert_key_path,
      }
    case SET_TLS_CERT_FILES:
      return {
        ...state,
        tls_cert_file: action.tls_cert_file,
        tls_cert_key_file: action.tls_cert_key_file,
      }
    case UPLOADING_TLS_CERT_PATHS:
      return {
        ...state,
        uploading_certs: action.uploading,
      }
    case TESTING_SYNAPSE_PORTS:
      return {
        ...state,
        verifying_ports: action.verifying,
      }
    case SET_SYNAPSE_PORTS:
      return {
        ...state,
        synapse_federation_port: action.federation_port,
        synapse_client_port: action.client_port,
      }
    case SET_SYNAPSE_PORTS_FREE:
      return {
        ...state,
        synapse_federation_port_free: action.synapse_federation_port_free,
        synapse_client_port_free: action.synapse_client_port_free,
      }
    case SET_DATABASE:
      return {
        ...state,
        database: action.database,
      }
    default:
      return state;
  }
};