import { connect } from 'react-redux';

import BaseIntro from '../components/BaseIntro';

import { advance_ui } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
  onClick: () => dispatch(advance_ui())
});

export default connect(
  null,
  mapDispathToProps
)(BaseIntro);