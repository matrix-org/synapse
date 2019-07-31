import fetchAbsolute from 'fetch-absolute';
import {
  API_URL,
  CONFIG,
  CONFIG_LOCK,
  CONFIG_SOMETHING,
  SECRET_KEY,
  SERVER_NAME,
  SETUP_CHECK,
} from './constants';

const fetchAbs = fetchAbsolute(fetch)(API_URL)

export const get_server_name = () => {
  fetchAbs(SERVER_NAME)
    .then(res => res.json())
};

export const post_server_name = () => {

};

export const get_secret_key = () => {
  fetchAbs(SECRET_KEY)
    .then(res => res.json())

};

export const get_config = () => {

};

export const post_config = () => {

};

// Checks if the server's base config has been setup.
export const get_server_setup = () => fetchAbs(SETUP_CHECK)
  .then(res => res.json()[CONFIG_LOCK])

