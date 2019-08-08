import { connect } from 'react-redux';

import Database from '../components/Database';
import { set_database, advance_ui, write_config } from '../actions';

const mapStateToProps = (state) => {
}


const mapDispatchToProps = (dispatch) => ({
  onClick: database => {
    dispatch(set_database(database));
    dispatch(advance_ui());
    dispatch(write_config())
  }
});

export default connect(
  null,
  mapDispatchToProps,
)(Database);