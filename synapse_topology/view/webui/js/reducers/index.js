import ui from './ui-reducer';
import base_config_reducer from './base-config-reducer';

import { LOADING_UI } from './ui_constants';

export default (state = { ui: { active_ui: LOADING_UI }, base_config: {} }, action) => ({
  ui: ui(state, action),
  base_config: base_config_reducer(state.base_config, action)
});