import { connect } from 'react-redux';

import StatsReporter from '../components/StatsReporter';

import { advance_ui, set_stats, generate_secret_keys } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
  onClick: consent => {
    dispatch(advance_ui());
    dispatch(set_stats(consent));
    dispatch(generate_secret_keys(consent))
  }
});

export default connect(
  null,
  mapDispathToProps
)(StatsReporter);