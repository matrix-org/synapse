import { combineReducers } from 'redux';
import ui from './reducer-ui';
import base_config from './reducer-base-config';
import { get_server_setup } from '../api';

export default combineReducers({
  ui,
  base_config
});