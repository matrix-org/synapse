import { combineReducers } from 'redux';
import ui from './reducer-ui';
import base_config from './reducer-base-config';
import { get_server_setup } from '../api';
import { LOADING_UI } from './ui_constants';

export default (state = { ui: { active_ui: LOADING_UI }, base_config: {} }, action) => ({
  ui: ui(state, action),
  base_config: base_config(state.base_config, action)
});