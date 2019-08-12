const ADVANCED_CONFIG_UI_COMPONENTS = {
  CONFIG_SELECTION_UI: "config_selection_ui"
}

export default ({ config_ui, base_config }, action) => {
  if (!base_config.base_config_checked) {
    return config_ui;
  }
  if (!base_config.setup_done) {
    return config_ui;
  }
  return config_ui;
}