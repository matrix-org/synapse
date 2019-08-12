import {
  ADVANCE_UI,
  BACK_UI,
  SET_SERVERNAME,
  SET_STATS,
  BASE_CONFIG_CHECKED,
  FAIL,
  SET_SECRET_KEY,
  GETTING_SECRET_KEY,
  SET_DELEGATION,
  SET_DELEGATION_SERVERNAME,
  SET_DELEGATION_PORTS,
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
  SET_CONFIG_DIR,
  WRITE_CONFIG,
} from './types';

import {
  get_server_setup,
  post_server_name,
  get_secretkey,
  post_cert_paths,
  post_certs,
  test_ports,
  post_config,
  start_synapse,
} from '../api';
import { CONFIG_LOCK, CONFIG_DIR } from '../api/constants';
import { base_config_to_synapse_config } from '../utils/yaml';

export const startup = () => {
  return dispatch => {
    get_server_setup().then(
      result => {
        dispatch(start(result[CONFIG_LOCK]));
        dispatch(set_config_dir(result[CONFIG_DIR]));
      },
      error => dispatch(fail(error)),
    )
  }
}

const set_config_dir = dir => ({
  type: SET_CONFIG_DIR,
  config_dir: dir,
});

export const generate_secret_keys = consent => {
  return (dispatch, getState) => {
    dispatch(getting_secret_keys());
    post_server_name(getState().base_config.servername, consent)
      .then(
        result => dispatch(get_secret_key()),
        error => dispatch(fail(error))
      )
  }
}

export const set_tls_cert_paths = (cert_path, cert_key_path) => {
  return dispatch => {
    dispatch(testing_tls_cert_paths(true));
    post_cert_paths(cert_path, cert_key_path)
      .then(
        result => dispatch(check_tls_cert_path_validity(result)),
        error => dispatch(fail(error))
      )
  }
}

const set_tls_certs = (cert_path, cert_key_path) => ({
  type: SET_TLS_CERT_PATHS,
  cert_path,
  cert_key_path,
})

const testing_tls_cert_paths = testing => ({
  type: TESTING_TLS_CERT_PATHS,
  testing,
});

const check_tls_cert_path_validity = (args) => {
  const { cert_path, cert_key_path } = args
  return dispatch => {
    dispatch(testing_tls_cert_paths(false));
    dispatch(set_tls_certs(cert_path.absolute_path, cert_key_path.absolute_path))
    dispatch(set_cert_path_validity({ cert_path, cert_key_path }));
    if (!cert_path.invalid && !cert_key_path.invalid) {
      dispatch(advance_ui());
    }
  }
}

export const upload_tls_cert_files = (tls_cert_file, tls_cert_key_file) =>
  dispatch => {
    dispatch(set_tls_cert_files(tls_cert_file, tls_cert_key_file));
    dispatch(uploading_tls_cert_files(true));
    post_certs(tls_cert_file, tls_cert_key_file)
      .then(
        result => {
          dispatch(uploading_tls_cert_files(false));
          dispatch(advance_ui())
        },
        error => dispatch(fail(error)),
      )
  }

const uploading_tls_cert_files = uploading => ({
  type: UPLOADING_TLS_CERT_PATHS,
  uploading
})

export const set_tls_cert_files = (tls_cert_file, tls_cert_key_file) => ({
  type: SET_TLS_CERT_FILES,
  tls_cert_file,
  tls_cert_key_file,
})
const set_cert_path_validity = ({ cert_path, cert_key_path }) => ({
  type: SET_TLS_CERT_PATHS_VALIDITY,
  cert_path_invalid: cert_path.invalid,
  cert_key_path_invalid: cert_key_path.invalid,
});

export const getting_secret_keys = () => ({
  type: GETTING_SECRET_KEY,
});

export const get_secret_key = () => {
  return dispatch => {
    get_secretkey().then(
      result => dispatch(set_secret_key(result)),
      error => dispatch(fail(error)),
    )
  }
}

export const set_secret_key = key => ({
  type: SET_SECRET_KEY,
  key,
});

export const start = setup_done => ({
  type: BASE_CONFIG_CHECKED,
  setup_done,
});

export const fail = reason => ({
  type: FAIL,
  reason,
});

export const advance_ui = option => ({
  type: ADVANCE_UI,
  option,
});

export const set_servername = servername => ({
  type: SET_SERVERNAME,
  servername,
});

export const set_stats = consent => ({
  type: SET_STATS,
  consent,
});

export const set_delegation = delegation_type => ({
  type: SET_DELEGATION,
  delegation_type,
});

export const set_delegation_servername = servername => ({
  type: SET_DELEGATION_SERVERNAME,
  servername,
});

export const set_delegation_ports = (federation_port, client_port) => ({
  type: SET_DELEGATION_PORTS,
  federation_port,
  client_port,
});

export const set_reverse_proxy = proxy_type => ({
  type: SET_REVERSE_PROXY,
  proxy_type,
});

export const set_tls = tls_type => ({
  type: SET_TLS,
  tls_type,
});

export const set_synapse_ports = (federation_port, client_port) => {
  const fed_port_priv = federation_port < 1024;
  const client_port_priv = client_port < 1024;
  return dispatch => {
    dispatch(testing_synapse_ports(true));
    dispatch({
      type: SET_SYNAPSE_PORTS,
      federation_port,
      client_port,
    })
    test_ports([federation_port, client_port])
      .then(
        results => dispatch(update_ports_free(
          fed_port_priv ? true : results.ports[0],
          client_port_priv ? true : results.ports[1]
        )),
        error => dispatch(fail(error)),
      )
  }
};

export const update_ports_free = (synapse_federation_port_free, synapse_client_port_free) => {
  return dispatch => {
    dispatch(testing_synapse_ports(false));
    dispatch({
      type: SET_SYNAPSE_PORTS_FREE,
      synapse_federation_port_free,
      synapse_client_port_free,
    });
    if (synapse_federation_port_free && synapse_client_port_free) {
      dispatch(advance_ui())
    }
  }
}

export const testing_synapse_ports = verifying => ({
  type: TESTING_SYNAPSE_PORTS,
  verifying,
})

export const set_database = database => ({
  type: SET_DATABASE,
  database,
})

export const write_config = (config, sub_config_name) => {
  return (dispatch, getState) => {
    post_config(base_config_to_synapse_config(getState().base_config), sub_config_name)
      .then(res => start_synapse(), error => dispatch(fail(error)))
  }
}