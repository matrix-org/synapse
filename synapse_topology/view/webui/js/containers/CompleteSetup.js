import { connect } from 'react-redux';

import CompleteSetup from '../components/CompleteSetup';
import { write_config } from '../actions';

const mapStateToProps = (state) => ({
  tlsType: state.base_config.tls,
  delegationType: state.base_config.delegation_type,
});


const mapDispatchToProps = (dispatch) => ({
  onClick: () => {
    dispatch(write_config())
  },
});

export default connect(
  mapStateToProps,
  mapDispatchToProps,
)(CompleteSetup);