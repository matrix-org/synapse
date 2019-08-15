import baseConfigReducer from './base-config-reducer';

import configUIReducer from './config-ui-reducer';
import setupUIReducer from './setup-ui-reducer';

import { SETUP_INTRO_UI, SERVER_NAME_UI } from './ui-constants';


export default (state = {
    setupUI: {
        activeBlocks: [SETUP_INTRO_UI, SERVER_NAME_UI],
    },
    configUI: {
    },
    baseConfig: {
        baseConfigChecked: false,
    },
}, action) => ({
    configUI: configUIReducer(state, action),
    setupUI: setupUIReducer(state, action),
    baseConfig: baseConfigReducer(state.baseConfig, action),
});