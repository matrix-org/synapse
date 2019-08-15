import { connect } from 'react-redux';

import BaseIntro from '../components/BaseIntro';

import { advanceUI } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
    onClick: () => dispatch(advanceUI()),
});

export default connect(
    null,
    mapDispathToProps,
)(BaseIntro);