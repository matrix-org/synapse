import { connect } from 'react-redux';

import Database from '../components/Database';
import { set_database, advance_ui } from '../actions';

const mapStateToProps = (state) => {
}


const mapDispatchToProps = (dispatch) => ({
  onClick: database => {
    dispatch(set_database(database));
    dispatch(advance_ui());
  }
});

export default connect(
  null,
  mapDispatchToProps,
)(Database);