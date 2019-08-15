import { ADVANCE_UI, BACK_UI, BASE_CONFIG_CHECKED } from '../actions/types';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle'
import {
  SETUP_ORDER,
} from './ui_constants';


const new_active_blocks = active_blocks => {
  return SETUP_ORDER.slice(0, active_blocks.length + 1)
}

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
        active_blocks: new_active_blocks(setup_ui.active_blocks),
      }
    case BACK_UI:
    default:
      return setup_ui;
  }
}

export const next_ui = current => SETUP_ORDER[SETUP_ORDER.lastIndexOf(current) + 1]