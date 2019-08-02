import { ADVANCE_UI, BACK_UI, BASE_CONFIG_CHECKED } from '../actions/types';

import {
  BASE_INTRO_UI,
  SERVER_NAME_UI,
  STATS_REPORT_UI,
  KEY_EXPORT_UI,
  DELEGATION_OPTIONS_UI,
  DELEGATION_SERVER_NAME_UI,
  WELL_KNOWN_UI,
  DNS_UI,
  WORKER_UI,
  TLS_UI,
  REVERSE_PROXY_UI,
  PORT_SELECTION_UI,
  REVERSE_PROXY_TEMPLATE_UI,
  LOADING_UI,
  TLS_CERTPATH_UI,
} from './ui_constants';

import {
  DELEGATION_TYPES, TLS_TYPES
} from '../actions/constants';

export default (state, action) => {
  switch (action.type) {
    case BASE_CONFIG_CHECKED:
      return BASE_INTRO_UI;
    case ADVANCE_UI:
      switch (state) {
        case BASE_INTRO_UI:
          return SERVER_NAME_UI;
        case SERVER_NAME_UI:
          return STATS_REPORT_UI;
        case STATS_REPORT_UI:
          return KEY_EXPORT_UI;
        case KEY_EXPORT_UI:
          return DELEGATION_OPTIONS_UI;
        case DELEGATION_OPTIONS_UI:
          switch (action.option) {
            // TODO: figure these out
            case DELEGATION_TYPES.DNS:
              return DELEGATION_SERVER_NAME_UI;
            case DELEGATION_TYPES.WELL_KNOWN:
              return DELEGATION_SERVER_NAME_UI;
            case DELEGATION_TYPES.LOCAL:
              return REVERSE_PROXY_UI;
            default:
              return DELEGATION_OPTIONS_UI;
          }
        case DELEGATION_SERVER_NAME_UI:
          return REVERSE_PROXY_UI;
        case REVERSE_PROXY_UI:
          return TLS_UI;
        case TLS_UI:
          switch (action.option) {
            case TLS_TYPES.ACME:
              return PORT_SELECTION_UI;
            case TLS_TYPES.TLS:
              return TLS_CERTPATH_UI;
            case TLS_TYPES.NONE:
              return PORT_SELECTION_UI;
          }
        case TLS_CERTPATH_UI:
          return PORT_SELECTION_UI;
        case WELL_KNOWN_UI:
        case DNS_UI:
        case PORT_SELECTION_UI:
          return WORKER_UI;
        case WORKER_UI:
          return REVERSE_PROXY_TEMPLATE_UI;
        default:
          return BASE_INTRO_UI;
      }

    // TODO: Think about how back should work..
    case BACK_UI:
      switch (state) {
        case STATS_REPORT_UI:
          return SERVER_NAME_UI;
        case KEY_EXPORT_UI:
          return STATS_REPORT_UI;
        case DELEGATION_OPTIONS_UI:
          return KEY_EXPORT_UI;
        case WELL_KNOWN_UI:
          return DELEGATION_OPTIONS_UI;
        case DNS_UI:
          return WELL_KNOWN_UI;
        default:
          BASE_INTRO_UI;
      }
    default:
      return state;
  }
}
