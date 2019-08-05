import { connect } from 'react-redux';

import DelegationPortSelection from '../components/DelegationPortSelection';

import { advance_ui, set_delegation_port } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
  onClick: port => {
    dispatch(advance_ui());
    dispatch(set_delegation_port(port));
  }
});

export default connect(
  null,
  mapDispathToProps
)(DelegationPortSelection);