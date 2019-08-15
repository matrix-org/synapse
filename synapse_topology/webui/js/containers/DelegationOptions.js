import { connect } from 'react-redux';

import DelegationOptions from '../components/DelegationOptions';
import { set_delegation, advance_ui, set_delegation_servername, set_delegation_ports } from '../actions';
import { DELEGATION_TYPES } from '../actions/constants';

const mapStateToProps = (state, { children }) => {
  return {
    servername: state.base_config.servername,
  }
}


const mapDispatchToProps = (dispatch) => ({
  onClick: (type, servername, fedPort, clientPort) => {
    dispatch(advance_ui());
    dispatch(set_delegation(type));
    dispatch(set_delegation_servername(servername));
    dispatch(set_delegation_ports(fedPort, clientPort));
  },

  skip: () => {
    dispatch(advance_ui());
    dispatch(set_delegation(DELEGATION_TYPES.LOCAL));
  }
});

export default connect(
  mapStateToProps,
  mapDispatchToProps,
)(DelegationOptions);