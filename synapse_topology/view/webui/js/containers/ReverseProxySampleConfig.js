import { connect } from 'react-redux';

import ReverseProxySampleConfig from '../components/ReverseProxySampleConfig';

import { advance_ui } from '../actions';
import { REVERSE_PROXY_TYPES } from '../actions/constants';

import apacheConfig from '../templates/apache';
import caddyConfig from '../templates/caddy';
import haproxyConfig from '../templates/haproxy';
import nginxConfig from '../templates/nginx';

const sampleConfig = reverseProxyType => {
  switch (reverseProxyType) {
    case REVERSE_PROXY_TYPES.APACHE:
      return apacheConfig;
    case REVERSE_PROXY_TYPES.CADDY:
      return caddyConfig;
    case REVERSE_PROXY_TYPES.HAPROXY:
      return haproxyConfig;
    case REVERSE_PROXY_TYPES.NGINX:
      return nginxConfig;
    case REVERSE_PROXY_TYPES.OTHER:
      return otherConfig;
  }
}

const mapStateToProps = state => ({
  proxyType: state.base_config.reverse_proxy,
  sampleConfig: sampleConfig(state.base_config.reverse_proxy)({
    delegationFedPort: state.base_config.delegation_federation_port ? state.base_config.delegation_federation_port : 8448,
    delegationClientPort: state.base_config.delegation_client_port ? state.base_config.delegation_client_port : 443,
    fedPort: state.base_config.synapse_federation_port,
    clientPort: state.base_config.synapse_client_port,
    synapseServerName: state.base_config.delegation_server_name ? state.base_config.delegation_server_name : state.base_config.servername,
  }),
  fileName: "synapse_reverse_proxy.conf",
});

const mapDispatchToProps = dispatch => ({
  onClick: () => dispatch(advance_ui()),
});

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(ReverseProxySampleConfig);