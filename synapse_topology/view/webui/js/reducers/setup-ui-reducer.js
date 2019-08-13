import { ADVANCE_UI, BACK_UI, BASE_CONFIG_CHECKED } from '../actions/types';

import {
  SETUP_INTRO_UI,
  SERVER_NAME_UI,
  STATS_REPORT_UI,
  KEY_EXPORT_UI,
  DELEGATION_OPTIONS_UI,
  TLS_UI,
  PORT_SELECTION_UI,
  REVERSE_PROXY_TEMPLATE_UI,
  DELEGATION_TEMPLATE_UI,
  DATABASE_UI,
} from './ui_constants';

import {
  DELEGATION_TYPES, TLS_TYPES
} from '../actions/constants';

export default ({ setup_ui, base_config }, action) => {
  if (!base_config.base_config_checked) {
    return setup_ui;
  }
  if (base_config.setup_done) {
    return setup_ui;
  }
  switch (action.type) {
    case ADVANCE_UI:
      return {
        active_blocks: [
          ...setup_ui.active_blocks,
          forward_mapping(
            setup_ui.active_blocks[setup_ui.active_blocks.length - 1],
            action,
            base_config,
          ),
        ]
      }
    case BACK_UI:
    default:
      return setup_ui;
  }
}

const forward_mapping = (current_ui, action, base_config) => {
  switch (current_ui) {
    case SETUP_INTRO_UI:
      return SERVER_NAME_UI;
    case SERVER_NAME_UI:
      return STATS_REPORT_UI;
    case STATS_REPORT_UI:
      return KEY_EXPORT_UI;
    case KEY_EXPORT_UI:
      return DELEGATION_OPTIONS_UI;
    case DELEGATION_OPTIONS_UI:
      return TLS_UI;
    case TLS_UI:
      return PORT_SELECTION_UI;
    case PORT_SELECTION_UI:
      return DATABASE_UI;
    case DATABASE_UI:
      return base_config.tls == TLS_TYPES.REVERSE_PROXY ?
        REVERSE_PROXY_TEMPLATE_UI :
        base_config.delegation_type != DELEGATION_TYPES.LOCAL ?
          DELEGATION_TEMPLATE_UI :
          DATABASE_UI;
    case REVERSE_PROXY_TEMPLATE_UI:
      return base_config.delegation_type != DELEGATION_TYPES.LOCAL ?
        DELEGATION_TEMPLATE_UI :
        DATABASE_UI;
    default:
      return SETUP_INTRO_UI;
  }
}
