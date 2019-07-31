import base_config_ui, { BASE_INTRO_UI } from './reducer-base-config-ui';
import advanced_config_ui from './reducer-advanced-config-ui';
import { BASE_CONFIG_CHECKED } from '../actions/types';
import { advance_ui } from '../actions';

export default (state, action) => {
  switch (action.type) {
    default:
      switch (action.base_config_done) {
        case true:
          return advanced_ui(state, action);
        case false:
          return base_config_ui(state, action);
      }

    case BASE_CONFIG_CHECKED:
      switch (action.base_config_done) {
        case true:
          return advanced_ui(state, action);
        case false:
          return base_config_ui(state, action);
      }
  }
}
