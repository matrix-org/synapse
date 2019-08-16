import { connect } from 'react-redux';

import PortSelection from '../components/PortSelection';

import { setSynapsePorts } from '../actions';
import { TLS_TYPES } from '../actions/constants';

const defaultFedPort = state => {

    if (state.tls == TLS_TYPES.REVERSE_PROXY) {

        return 8008;

    }

    return state.delegationFederationPort ? state.delegationFederationPort : 8448;

}

const defaultClientPort = state => {

    if (state.tls == TLS_TYPES.REVERSE_PROXY) {

        return 8008;

    }

    return state.delegationFederationPort ?
        state.delegationFederationPort :
        443;

}

const mapStateToProps = ({ baseConfig }) => ({
    servername: baseConfig.servername,
    verifyingPorts: baseConfig.verifyingPorts,
    fedPortInUse: baseConfig.synapseFederationPortFree != undefined ?
        !baseConfig.synapseFederationPortFree :
        false,
    clientPortInUse: baseConfig.synapseClientPortFree != undefined ?
        !baseConfig.synapseClientPortFree :
        false,
    canChangePorts: baseConfig.tls == TLS_TYPES.REVERSE_PROXY,
    defaultFedPort: defaultFedPort(baseConfig),
    defaultClientPort: defaultClientPort(baseConfig),
});

const mapDispathToProps = (dispatch) => ({
    onClick: (fedPort, clientPort, callback) => {

        dispatch(setSynapsePorts(fedPort, clientPort, callback));

    },
});

export default connect(
    mapStateToProps,
    mapDispathToProps,
)(PortSelection);