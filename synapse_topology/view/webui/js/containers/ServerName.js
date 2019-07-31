import { connect } from 'react-redux';

import ServerName from '../components/ServerName';

import { advance_ui, set_servername } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
  onClick: servername => {
    dispatch(advance_ui());
    dispatch(set_servername(servername));
  }
});

export default connect(
  null,
  mapDispathToProps
)(ServerName);