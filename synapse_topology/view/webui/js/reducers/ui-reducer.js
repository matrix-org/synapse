import setup_ui_reducer from './setup-ui-reducer';
import config_ui_reducer from './config-ui-reducer';
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
      if (action.setup_done) {
        return {
          setup_done: true,
          config_ui: config_ui_reducer(state, action),
        }
      } else {
        return {
          setup_done: false,
          setup_ui: setup_ui_reducer(state, action),
        }
      }
    default:
      const newstate = { ...state.ui };
      if ('setup_done' in state.ui) {
        if (state.ui.setup_done) {
          newstate.config_ui = config_ui_reducer(state, action);
        } else {
          newstate.setup_ui = setup_ui_reducer(state, action);
        }
      }
      return newstate;
  }
}
