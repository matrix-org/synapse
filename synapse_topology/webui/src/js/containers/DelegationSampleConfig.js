import { connect } from 'react-redux';

import DelegationSampleConfig from '../components/DelegationSampleConfig';

import { advanceUI } from '../actions';

import DNSConfig from '../templates/dns-srv';
import FedWellKnownConfig from '../templates/federation-well-known'
import ClientWellKnownConfig from '../templates/client-well-known'
import { DELEGATION_TYPES } from '../actions/constants';

// synapseServerName: state.baseConfig.delegationServerName ? state.baseConfig.delegationServerName : state.baseConfig.servername,

const serverConfig = state => {

    if (state.delegationType == DELEGATION_TYPES.DNS) {

        return undefined;

    } else {

        return FedWellKnownConfig({
            synapseServerName: state.delegationServerName,
            delegationSynapsePort: state.delegationFederationPort ?
                state.delegationFederationPort :
                8448,
        });

    }

}

const clientConfig = state => {

    if (state.delegationType == DELEGATION_TYPES.WELL_KNOWN) {

        return ClientWellKnownConfig({
            synapseServerName: state.delegationServerName,
            delegationClientPort: state.delegationClientPort ?
                state.delegationClientPort :
                443,
        });

    } else {

        return DNSConfig({
            serverName: state.servername,
            synapseServerName: state.delegationServerName,
            delegationClientPort: state.delegationClientPort ?
                state.delegationClientPort :
                443,
        })

    }

}

const mapStateToProps = state => ({
    delegationType: state.baseConfig.delegationType,
    serverConfig: serverConfig(state.baseConfig),
    clientConfig: clientConfig(state.baseConfig),
    serverConfigFileName: `${state.baseConfig.servername}_delegation.conf`,
    clientConfigFileName: `${state.baseConfig.servername}_client_delegation.conf`,
    serverName: state.baseConfig.servername,
});

const mapDispatchToProps = dispatch => ({
    onClick: () => dispatch(advanceUI()),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps,
)(DelegationSampleConfig);