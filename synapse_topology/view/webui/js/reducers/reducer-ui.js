import base_config_ui from './reducer-base-config-ui';
import advanced_config_ui from './reducer-advanced-config-ui';
import { LOADING_UI, ERROR_UI } from './ui_constants';
import { BASE_CONFIG_CHECKED, FAIL } from '../actions/types';


export default (state = { active_ui: LOADING_UI }, action) => {
  console.log(action)
  switch (action.type) {
    case FAIL:
      return {
        ...state,
        active_ui: ERROR_UI
      }
    case BASE_CONFIG_CHECKED:
      if (action.base_config_done) {
        return {
          base_config_done: true,
          active_ui: advanced_config_ui(state.active_ui, action),
        }
      } else {
        return {
          base_config_done: false,
          active_ui: base_config_ui(state.active_ui, action),
        }
      }
    default:
      const newstate = { ...state };
      if ('base_config_done' in state) {
        if (state.base_config_done) {
          newstate.active_ui = advanced_ui(state.active_ui, action);
        } else {
          newstate.active_ui = base_config_ui(state.active_ui, action);
        }
      }
      return newstate;
  }
}
