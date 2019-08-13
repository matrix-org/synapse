import base_config_reducer from './base-config-reducer';

import config_ui_reducer from './config-ui-reducer';
import setup_ui_reducer from './setup-ui-reducer';

import { SETUP_INTRO_UI, SERVER_NAME_UI } from './ui_constants';


export default (state = {
  setup_ui: {
    active_blocks: [SETUP_INTRO_UI, SERVER_NAME_UI],
  },
  config_ui: {
  },
  base_config: {
    base_config_checked: false,
  }
}, action) => ({
  config_ui: config_ui_reducer(state, action),
  setup_ui: setup_ui_reducer(state, action),
  base_config: base_config_reducer(state.base_config, action)
});