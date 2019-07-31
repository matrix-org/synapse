import { combineReducers } from 'redux';
import ui from './reducer-ui';
import base_config from './reducer-base-config';
import { get_server_setup } from '../api/api';

export default combineReducers({
  ui,
  base_config
});

export const initial_state = () => ({
  ui: { base_config_done: await get_server_setup() }
})