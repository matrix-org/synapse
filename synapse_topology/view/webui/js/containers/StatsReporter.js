import { connect } from 'react-redux';

import StatsReporter from '../components/StatsReporter';

import { advance_ui, set_stats } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
  onClick: consent => {
    dispatch(advance_ui());
    dispatch(set_stats(consent));
  }
});

export default connect(
  null,
  mapDispathToProps
)(StatsReporter);