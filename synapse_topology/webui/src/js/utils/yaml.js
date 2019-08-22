/* eslint-disable camelcase */
import { TLS_TYPES, REVERSE_PROXY_TYPES } from '../actions/constants';
import { CONFIG_LOCK } from '../api/constants';

const listeners = config => {

    const listeners = [];
    if (config.tls == TLS_TYPES.REVERSE_PROXY) {

        listeners.push({
            port: config.synapseFederationPort,
            tls: false,
            bind_addresses: ['::1', '127.0.0.1'],
            type: "http",
            x_forwarded: true,

            resources: [{
                names: ["federation"],
                compress: false,
            }],
        });

    } else {

        listeners.push({
            port: config.synapseFederationPort,
            tls: true,
            type: "http",

            resources: [{
                names: ["federation"],
            }],
        });

    }

    if (config.synapseClientPort == config.synapseFederationPort) {

        listeners[0].resources[0].names.push("client");

    } else if (config.tls == TLS_TYPES.REVERSE_PROXY) {

        listeners.push({
            port: config.synapseClientPort,
            tls: false,
            bind_addresses: ['::1', '127.0.0.1'],
            type: "http",
            x_forwarded: true,

            resources: [{
                names: ["client"],
                compress: false,
            }],
        });

    } else {

        listeners.push({
            port: config.synapseClientPort,
            tls: true,
            type: "http",

            resources: [{
                names: ["client"],
            }],
        });

    }
    return { listeners: listeners };

}

const tlsPaths = config => {

    if (config.tls == TLS_TYPES.TLS) {

        return {
            tls_certificate_path: config.tlsCertPath,
            tls_private_key_path: config.tlsCertKeyPath,
        }

    } else if (config.tls == TLS_TYPES.ACME) {

        return {
            tls_certificate_path:
                config.configDir + "/" + config.servername + ".tls.cert",
            tls_private_key_path:
                config.configDir + "/" + config.servername + ".tls.key",
        }

    } else {

        return {}

    }

}

const acme = config => {

    if (config.tls == TLS_TYPES.ACME) {

        return {
            acme_domain: config.delegationServerName ?
                config.delegationServerName :
                config.servername,
        }

    } else {

        return {}

    }

}

const database = config => ({
    database: {
        name: config.database,
        args: {
            database: config.configDir + "/data/homeserver.db",
        },
    },
})

export const baseConfigToSynapseConfig = config => {

    const conf = {
        server_name: config.servername,
        report_stats: config.reportStats,
        ...listeners(config),
        ...tlsPaths(config),
        ...acme(config),
        ...database(config),
        [CONFIG_LOCK]: true,
    }
    console.log(conf)
    return conf

}
