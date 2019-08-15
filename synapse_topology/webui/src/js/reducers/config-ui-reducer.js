const ADVANCED_CONFIG_UI_COMPONENTS = {
    CONFIG_SELECTION_UI: "config_selection_ui",
};

export default ({ configUI, baseConfig }, action) => {

    if (!baseConfig.baseConfigChecked) {

        return configUI;

    };

    if (!baseConfig.setupDone) {

        return configUI;

    };

    return configUI;

}