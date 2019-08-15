import fetchAbsolute from 'fetch-absolute';
import {
  API_URL,
  CONFIG,
  SECRET_KEY,
  SERVER_NAME,
  SETUP_CHECK,
  CERT_PATHS,
  TEST_PORTS,
  START,
} from './constants';

const fetchAbs = fetchAbsolute(fetch)(API_URL)

export const get_server_name = () =>
  fetchAbs(SERVER_NAME)
    .then(res => res.json())

export const post_server_name = (servername, consent) =>
  fetchAbs(
    SERVER_NAME,
    {
      method: 'POST',
      body: JSON.stringify({
        "server_name": servername,
        "report_stats": consent
      })
    }
  )

export const post_cert_paths = (cert_path, cert_key_path) =>
  fetchAbs(
    CERT_PATHS,
    {
      method: 'POST',
      body: JSON.stringify({
        cert_path,
        cert_key_path,
      })
    }
  ).then(res => res.json())

export const post_certs = (cert, cert_key) =>
  fetchAbs(
    CERT_PATHS,
    {
      method: 'POST',
      body: JSON.stringify({
        cert,
        cert_key,
      })
    }
  )

export const test_ports = (ports) =>
  fetchAbs(
    TEST_PORTS,
    {
      method: 'POST',
      body: JSON.stringify({
        ports
      })
    }
  ).then(res => res.json())

export const get_secretkey = () =>
  fetchAbs(SECRET_KEY)
    .then(res => res.json())
    .then(json => json.secret_key)

export const get_config = () => {

};

export const post_config = (config, sub_config_name) =>
  fetchAbs(
    sub_config_name ? CONFIG + "/" + sub_config_name : CONFIG,
    {
      method: 'POST',
      body: JSON.stringify(config),
    }
  )


// Checks if the server's base config has been setup.
export const get_server_setup = () => fetchAbs(SETUP_CHECK)
  .then(res => res.json())

export const start_synapse = () => fetchAbs(START)