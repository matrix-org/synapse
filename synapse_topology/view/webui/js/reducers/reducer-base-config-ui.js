import { ADVANCE_UI, BACK_UI } from '../actions/types';

export const BASE_INTRO_UI = "INTRO_UI";
export const SERVER_NAME_UI = "server_name_ui";
export const STATS_REPORT_UI = "stats_report_ui";
export const KEY_EXPORT_UI = "key_export_ui";
export const DELEGATION_OPTIONS_UI = "delegation_options_ui";
export const WELL_KNOWN_UI = "well_known_ui";
export const DNS_UI = "dns_ui";
export const WORKER_UI = "worker_ui";
export const ACME_UI = "acme_ui";
export const REVERSE_PROXY_UI = "reverse_proxy_ui";
export const PORT_SELECTION_UI = "port_selection_ui";
export const REVERSE_PROXY_TEMPLATE_UI = "reverse_proxy_tamplate_ui";

export default (state, action) => {
  switch (action.type) {
    case ADVANCE_UI:
      switch (state) {
        case BASE_INTRO_UI:
          return SERVER_NAME_UI;
        case SERVER_NAME_UI:
          return STATS_REPORT_UI;
        case STATS_REPORT_UI:
          return KEY_EXPORT_UI;
        case DELEGATION_OPTIONS_UI:
          switch (action.option) {
            // TODO: figure these out
            case "DNS":
              return DNS_UI;
            case "WELL_KNOWN":
              return WELL_KNOWN_UI;
            case "NO_DELEGATION":
              return ACME_UI;
            default:
              return DELEGATION_OPTIONS_UI;
          }
        case WELL_KNOWN_UI:
          return ACME_UI;
        case DNS_UI:
          return ACME_UI;
        case ACME_UI:
          return REVERSE_PROXY_UI;
        case REVERSE_PROXY_UI:
          return PORT_SELECTION_UI;
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
