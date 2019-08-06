import { connect } from 'react-redux';

import PortSelection from '../components/PortSelection';

import { set_synapse_ports } from '../actions';
import { TLS_TYPES } from '../actions/constants';

const defaultFedPort = state => {
  console.log(state)
  if (state.tls == TLS_TYPES.REVERSE_PROXY) {
    return 8008;
  }

  return state.delegation_federation_port ? state.delegation_federation_port : 8448;
}

const defaultClientPort = state => {
  if (state.tls == TLS_TYPES.REVERSE_PROXY) {
    return 8008;
  }

  return state.delegation_federation_port ? state.delegation_federation_port : 443;
}

const mapStateToProps = (state, ownProps) => ({
  servername: state.base_config.servername,
  verifyingPorts: state.base_config.verifying_ports,
  fedPortInUse: !state.base_config.synapse_federation_port_free,
  clientPortInUse: !state.base_config.synapse_client_port_free,
  canChangePorts: state.base_config.tls == TLS_TYPES.REVERSE_PROXY,
  defaultFedPort: defaultFedPort(state.base_config),
  defaultClientPort: defaultClientPort(state.base_config),
});

const mapDispathToProps = (dispatch) => ({
  onClick: (fedPort, clientPort) => {
    dispatch(set_synapse_ports(fedPort, clientPort));
  }
});

export default connect(
  mapStateToProps,
  mapDispathToProps
)(PortSelection);