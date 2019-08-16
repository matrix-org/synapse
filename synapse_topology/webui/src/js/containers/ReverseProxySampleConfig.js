import { connect } from 'react-redux';

import ReverseProxySampleConfig from '../components/ReverseProxySampleConfig';

import { advanceUI } from '../actions';
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
    proxyType: state.baseConfig.reverseProxy,
    sampleConfig: sampleConfig(state.baseConfig.reverseProxy)({
        delegationFedPort: state.baseConfig.delegationFederationPort ?
            state.baseConfig.delegationFederationPort :
            8448,
        delegationClientPort: state.baseConfig.delegationClientPort ?
            state.baseConfig.delegationClientPort :
            443,
        fedPort: state.baseConfig.synapseFederationPort,
        clientPort: state.baseConfig.synapseClientPort,
        synapseServerName: state.baseConfig.delegationServerName ?
            state.baseConfig.delegationServerName :
            state.baseConfig.servername,
    }),
    fileName: "synapse_reverse_proxy.conf",
});

const mapDispatchToProps = (dispatch, { onClick }) => ({
    onClick,
});

export default connect(
    mapStateToProps,
    mapDispatchToProps,
)(ReverseProxySampleConfig);