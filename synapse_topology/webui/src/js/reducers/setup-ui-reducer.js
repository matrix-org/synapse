import { ADVANCE_UI, BACK_UI, BASE_CONFIG_CHECKED } from '../actions/types';
import {
    SETUP_ORDER,
} from './ui-constants';


const newActiveBlocks = activeBlocks => {

    return SETUP_ORDER.slice(0, activeBlocks.length + 1)

}

export default ({ setupUI, baseConfig }, action) => {

    if (!baseConfig.baseConfigChecked) {

        return setupUI;

    }
    if (baseConfig.setupDone) {

        return setupUI;

    }
    switch (action.type) {

        case ADVANCE_UI:
            return {
                activeBlocks: newActiveBlocks(setupUI.activeBlocks),
            };
        case BACK_UI:
            return {
                activeBlocks: resetUI(setupUI.activeBlocks, action.ui),
            };
        default:
            return setupUI;

    }

}

export const nextUI = current => SETUP_ORDER[SETUP_ORDER.lastIndexOf(current) + 1]

export const resetUI = (activeBlocks, destinationBlock) => {

    const indexOfDest = SETUP_ORDER.indexOf(destinationBlock);

    if (indexOfDest >= activeBlocks.length) {

        // The index is in the future
        return activeBlocks;

    }

    return activeBlocks.slice(0, indexOfDest + 1);

}