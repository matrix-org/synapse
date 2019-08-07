import base_config_ui from './reducer-base-config-ui';
import advanced_config_ui from './reducer-advanced-config-ui';
import { LOADING_UI, ERROR_UI } from './ui_constants';
import { BASE_CONFIG_CHECKED, FAIL } from '../actions/types';


export default (state, action) => {
  console.log(state)
  console.log(action)
  switch (action.type) {
    case FAIL:
      return {
        ...state.ui,
        active_ui: ERROR_UI
      }
    case BASE_CONFIG_CHECKED:
      if (action.base_config_done) {
        return {
          base_config_done: true,
          active_ui: advanced_config_ui(state, action),
        }
      } else {
        return {
          base_config_done: false,
          active_ui: base_config_ui(state, action),
        }
      }
    default:
      const newstate = { ...state.ui };
      if ('base_config_done' in state.ui) {
        if (state.ui.base_config_done) {
          newstate.active_ui = advanced_ui(state, action);
        } else {
          newstate.active_ui = base_config_ui(state, action);
        }
      }
      return newstate;
  }
}
