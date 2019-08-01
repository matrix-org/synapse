import { connect } from 'react-redux';

import DelegationServerName from '../components/DelegationServerName';

import { advance_ui, set_delegation_servername } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
  onClick: servername => {
    dispatch(advance_ui());
    dispatch(set_delegation_servername(servername));
  }
});

export default connect(
  null,
  mapDispathToProps
)(DelegationServerName);