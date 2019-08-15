import { connect } from 'react-redux';

import CompleteSetup from '../components/CompleteSetup';
import { writeConfig } from '../actions';

const mapStateToProps = (state) => ({
    tlsType: state.baseConfig.tls,
    delegationType: state.baseConfig.delegationType,
});


const mapDispatchToProps = (dispatch) => ({
    onClick: () => dispatch(writeConfig()),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps,
)(CompleteSetup);