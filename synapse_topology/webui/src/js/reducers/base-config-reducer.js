import {
    SET_SERVERNAME,
    SET_STATS,
    SET_SECRET_KEY,
    GETTING_SECRET_KEY,
    SET_DELEGATION,
    SET_DELEGATION_PORTS,
    SET_DELEGATION_SERVERNAME,
    SET_REVERSE_PROXY,
    SET_TLS,
    TESTING_TLS_CERT_PATHS,
    SET_TLS_CERT_PATHS,
    SET_TLS_CERT_PATHS_VALIDITY,
    SET_TLS_CERT_FILES,
    UPLOADING_TLS_CERT_PATHS,
    TESTING_SYNAPSE_PORTS,
    SET_SYNAPSE_PORTS,
    SET_SYNAPSE_PORTS_FREE,
    SET_DATABASE,
    SET_CONFIG_DIR,
    BASE_CONFIG_CHECKED,
    SYNAPSE_START,
} from "../actions/types";

export default (state, action) => {

    switch (action.type) {

        case BASE_CONFIG_CHECKED:
            return {
                ...state,
                baseConfigChecked: true,
                setupDone: action.setupDone,
            }
        case SET_SERVERNAME:
            return {
                ...state,
                servername: action.servername,
            }
        case SET_STATS:
            return {
                ...state,
                reportStats: action.consent,
            }
        case GETTING_SECRET_KEY:
            return {
                ...state,
                secretKeyLoaded: false,
            }
        case SET_SECRET_KEY:
            return {
                ...state,
                secretKeyLoaded: true,
                secretKey: action.key,
            };
        case SET_DELEGATION:
            return {
                ...state,
                delegationType: action.delegationType,
            }
        case SET_DELEGATION_PORTS:
            return {
                ...state,
                delegationFederationPort: action.federationPort,
                delegationClientPort: action.clientPort,
            }
        case SET_DELEGATION_SERVERNAME:
            return {
                ...state,
                delegationServername: action.servername,
            }
        case SET_REVERSE_PROXY:
            return {
                ...state,
                reverseProxy: action.proxyType,
            }
        case SET_TLS:
            return {
                ...state,
                tls: action.tlsType,
            }
        case TESTING_TLS_CERT_PATHS:
            return {
                ...state,
                testingCertPaths: action.testing,
            }
        case SET_TLS_CERT_PATHS_VALIDITY:
            return {
                ...state,
                certPathInvalid: action.certPathInvalid,
                certKeyPathInvalid: action.certKeyPathInvalid,
            }
        case SET_TLS_CERT_PATHS:
            return {
                ...state,
                tlsCertPath: action.certPath,
                tlsCertKeyPath: action.certKeyPath,
            }
        case SET_TLS_CERT_FILES:
            return {
                ...state,
                tlsCertFile: action.tlsCertFile,
                tlsCertKeyFile: action.tlsCerKeyFile,
            }
        case UPLOADING_TLS_CERT_PATHS:
            return {
                ...state,
                uploadingCerts: action.uploading,
            }
        case TESTING_SYNAPSE_PORTS:
            return {
                ...state,
                verifyingports: action.verifying,
            }
        case SET_SYNAPSE_PORTS:
            return {
                ...state,
                synapseFederationPort: action.federationPort,
                synapseClientPort: action.clientPort,
            }
        case SET_SYNAPSE_PORTS_FREE:
            return {
                ...state,
                synapseFederationPortFree: action.synapseFederationPortFree,
                synapseClientPortFree: action.synapseClientPortFree,
            }
        case SET_DATABASE:
            return {
                ...state,
                ...action.databaseConfig,
            }
        case SET_CONFIG_DIR:
            return {
                ...state,
                configDir: action.configDir,
            }
        case SYNAPSE_START:
            return {
                ...state,
                synapseStartedFailed: true,
            }
        default:
            return state;

    }

};