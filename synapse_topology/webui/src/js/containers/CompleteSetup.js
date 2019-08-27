import { connect } from 'react-redux';

import CompleteSetup from '../components/CompleteSetup';
import { writeConfig } from '../actions';

const mapStateToProps = (state) => ({
    tlsType: state.baseConfig.tls,
    synapseStartFailed: state.baseConfig.synapseStartFailed,
    delegationType: state.baseConfig.delegationType,
    configDir: state.baseConfig.configDir,
});


const mapDispatchToProps = (dispatch) => ({
    onClick: () => dispatch(writeConfig()),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps,
)(CompleteSetup);