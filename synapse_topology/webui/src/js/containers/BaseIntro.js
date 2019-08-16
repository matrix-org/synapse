import { connect } from 'react-redux';

import BaseIntro from '../components/BaseIntro';

import { advanceUI } from '../actions';

const mapStateToProps = (state, ownProps) => ({
    started: Boolean(state.setupUI.activeBlocks.length),
    servername: state.baseConfig.servername,
});

const mapDispathToProps = (dispatch) => ({
    onClick: () => dispatch(advanceUI()),
});

export default connect(
    mapStateToProps,
    mapDispathToProps,
)(BaseIntro);