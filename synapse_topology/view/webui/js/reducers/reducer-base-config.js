import {
  SET_SERVERNAME,
  SET_STATS,
  SET_SECRET_KEY,
  GETTING_SECRET_KEY,
  SET_DELEGATION,
  SET_DELEGATION_SERVERNAME,
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
        delegation_servername: action.delegation_servername,
      }
    default:
      return state;
  }
};