import { connect } from 'react-redux';

import DelegationOptions from '../components/DelegationOptions';
import { set_delegation, advance_ui } from '../actions';
import { DELEGATION_TYPES } from '../actions/constants';

const mapStateToProps = (state, { children }) => {
  return {
    servername: state.base_config.servername,
  }
}


const mapDispatchToProps = (dispatch) => ({
  clickLocal: () => {
    dispatch(advance_ui(DELEGATION_TYPES.LOCAL));
    dispatch(set_delegation(DELEGATION_TYPES.LOCAL));
  },
  clickWellKnown: () => {
    dispatch(advance_ui(DELEGATION_TYPES.WELL_KNOWN));
    dispatch(set_delegation(DELEGATION_TYPES.WELL_KNOWN));
  },
  clickDNS: () => {
    dispatch(advance_ui(DELEGATION_TYPES.DNS));
    dispatch(set_delegation(DELEGATION_TYPES.DNS));
  }
});

export default connect(
  mapStateToProps,
  mapDispatchToProps,
)(DelegationOptions);