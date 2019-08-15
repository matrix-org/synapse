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

const mapStateToProps = ({ base_config }) => ({
  servername: base_config.servername,
  verifyingPorts: base_config.verifying_ports,
  fedPortInUse: base_config.synapse_federation_port_free != undefined ? !base_config.synapse_federation_port_free : false,
  clientPortInUse: base_config.synapse_client_port_free != undefined ? !base_config.synapse_client_port_free : false,
  canChangePorts: base_config.tls == TLS_TYPES.REVERSE_PROXY,
  defaultFedPort: defaultFedPort(base_config),
  defaultClientPort: defaultClientPort(base_config),
});

const mapDispathToProps = (dispatch) => ({
  onClick: (fedPort, clientPort, callback) => {
    dispatch(set_synapse_ports(fedPort, clientPort, callback));
  }
});

export default connect(
  mapStateToProps,
  mapDispathToProps
)(PortSelection);