import { connect } from 'react-redux';

import DelegationSampleConfig from '../components/DelegationSampleConfig';

import { advance_ui } from '../actions';

import DNSConfig from '../templates/dns-srv';
import FedWellKnownConfig from '../templates/federation-well-known'
import ClientWellKnownConfig from '../templates/client-well-known'
import { DELEGATION_TYPES } from '../actions/constants';

// synapseServerName: state.base_config.delegation_server_name ? state.base_config.delegation_server_name : state.base_config.servername,

const serverConfig = state => {
  if (state.delegation_type == DELEGATION_TYPES.DNS) {
    return undefined;
  } else {
    return FedWellKnownConfig({
      synapseServerName: state.delegation_servername,
      delegationSynapsePort: state.delegation_federation_port ? state.delegation_federation_port : 8448,
    });
  }
}

const clientConfig = state => {
  if (state.delegation_type == DELEGATION_TYPES.WELL_KNOWN) {
    return ClientWellKnownConfig({
      synapseServerName: state.delegation_servername,
      delegationClientPort: state.delegation_client_port ? state.delegation_client_port : 443,
    });
  } else {
    return DNSConfig({
      serverName: state.servername,
      synapseServerName: state.delegation_servername,
      delegationClientPort: state.delegation_client_port ? state.delegation_client_port : 443,
    })
  }
}

const mapStateToProps = state => ({
  delegationType: state.base_config.delegation_type,
  serverConfig: serverConfig(state.base_config),
  clientConfig: clientConfig(state.base_config),
  serverConfigFileName: `${state.base_config.servername}_delegation.conf`,
  clientConfigFileName: `${state.base_config.servername}_client_delegation.conf`,
  serverName: state.base_config.servername,
});

const mapDispatchToProps = dispatch => ({
  onClick: () => dispatch(advance_ui()),
});

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(DelegationSampleConfig);