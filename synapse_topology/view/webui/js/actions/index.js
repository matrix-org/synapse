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
} from './types';

import { get_server_setup, post_server_name, fetch_secret_key } from '../api';

export const startup = () => {
  return dispatch => {
    get_server_setup().then(
      result => dispatch(start(result)),
      error => dispatch(fail(error))
    )
  }
}

export const generate_secret_keys = consent => {
  return (dispatch, getState) => {
    dispatch(getting_secret_keys());
    post_server_name(getState().base_config.servername, consent)
      .then(dispatch(get_secret_key()))
  }
}

export const getting_secret_keys = () => ({
  type: GETTING_SECRET_KEY
});

export const get_secret_key = () => {
  return dispatch => {
    fetch_secret_key().then(
      result => dispatch(set_secret_key(result)),
      error => dispatch(fail(error))
    )
  }
}

export const set_secret_key = key => ({
  type: SET_SECRET_KEY,
  key
});

export const start = server_setup => ({
  type: BASE_CONFIG_CHECKED,
  base_config_done: server_setup,
});

export const fail = reason => ({
  type: FAIL,
  reason
});

export const advance_ui = option => ({
  type: ADVANCE_UI,
  option
});

export const set_servername = servername => ({
  type: SET_SERVERNAME,
  servername
});

export const set_stats = consent => ({
  type: SET_STATS,
  consent
});

export const set_delegation = delegation_type => ({
  type: SET_DELEGATION,
  delegation_type
})

export const set_delegation_servername = servername => ({
  type: SET_DELEGATION_SERVERNAME,
  servername
})