import baseConfigReducer from './base-config-reducer';

import configUIReducer from './config-ui-reducer';
import setupUIReducer from './setup-ui-reducer';

import { SETUP_INTRO_UI, SERVER_NAME_UI } from './ui-constants';

import { uiStateMapping } from './state';
import { BACK_UI } from '../actions/types';

export default (state = {
    setupUI: {
        activeBlocks: [SETUP_INTRO_UI, SERVER_NAME_UI],
    },
    configUI: {
    },
    baseConfig: {
        baseConfigChecked: false,
    },
}, action) => {

    const setupUI = setupUIReducer(state, action);

    const rState = {
        configUI: configUIReducer(state, action),
        setupUI,
        baseConfig: filterBaseConfig(
            baseConfigReducer(state.baseConfig, action),
            action,
            setupUI.activeBlocks.slice(0, setupUI.activeBlocks.length - 1),
        ),
    }

    console.log(action);
    console.log(rState);

    return rState;

};

const filterBaseConfig = (baseConfig, action, activeBlocks) => {

    if (action.type == BACK_UI) {

        return filterObj(
            baseConfig,
            Object.values(
                filterObj(
                    uiStateMapping,
                    [...activeBlocks, "base"]),
            ).flat(),
        );

    } else {

        return baseConfig;

    }

}

const filterObj = (object, filterList) => {

    return Object.keys(object)
        .filter(key => filterList.includes(key))
        .reduce((obj, key) => {

            obj[key] = object[key];
            return obj;

        },
            {},
        );

}

