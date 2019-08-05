import { connect } from 'react-redux';

import DelegationPortSelection from '../components/DelegationPortSelection';

import { advance_ui, set_delegation_ports } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
  onClick: (fedPort, clientPort) => {
    dispatch(advance_ui());
    dispatch(set_delegation_ports(fedPort, clientPort));
  }
});

export default connect(
  null,
  mapDispathToProps
)(DelegationPortSelection);