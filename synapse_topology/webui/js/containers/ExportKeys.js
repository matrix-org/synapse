import { connect } from 'react-redux';

import ExportKeys from '../components/ExportKeys';

import { advance_ui } from '../actions';

const mapStateToProps = (state, ownProps) => {
  const secret_key_loaded = state.base_config.secret_key_loaded;
  const secret_key = state.base_config.secret_key;
  return {
    secret_key_loaded,
    secret_key,
  }
};

const mapDispatchToProps = (dispatch) => ({
  onClick: () => dispatch(advance_ui())
});

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(ExportKeys);