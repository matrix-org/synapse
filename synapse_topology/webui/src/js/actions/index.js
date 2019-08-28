import {
    ADVANCE_UI,
    BACK_UI,
    SET_SERVERNAME,
    SET_STATS,
    BASE_CONFIG_CHECKED,
    FAIL,
    SET_SECRET_KEY,
    GETTING_SECRET_KEY,
    SET_DELEGATION,
    SET_DELEGATION_SERVERNAME,
    SET_DELEGATION_PORTS,
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
    SYNAPSE_START_FAILED,
} from './types';

import {
    getServerSetup,
    getSecretkey,
    postCertPaths,
    postCerts,
    testPorts,
    postConfig,
    startSynapse,
} from '../api';

import { CONFIG_LOCK, CONFIG_DIR } from '../api/constants';
import { baseConfigToSynapseConfig } from '../utils/yaml';

export const startup = () => {

    return dispatch => {

        getServerSetup().then(
            result => {

                dispatch(start(result[CONFIG_LOCK]));
                dispatch(setConfigDir(result[CONFIG_DIR]));

            },
            error => dispatch(fail(error)),
        )

    };

};

const setConfigDir = dir => ({
    type: SET_CONFIG_DIR,
    configDir: dir,
});

export const generateSecretKeys = serverName => {

    return dispatch => {
        dispatch(getSecretKey(serverName))
    };

};

export const setTlsCertPaths = (certPath, certKeyPath, callback) => {

    return dispatch => {

        dispatch(testingTlsCertPaths(true));
        postCertPaths(certPath, certKeyPath)
            .then(
                result => dispatch(checkTlsCertPathValidity(result, callback)),
                error => dispatch(fail(error)),
            );

    };

};

const setTlsCerts = (certPath, certKeyPath) => ({
    type: SET_TLS_CERT_PATHS,
    certPath: certPath,
    certKeyPath: certKeyPath,
});

const testingTlsCertPaths = testing => ({
    type: TESTING_TLS_CERT_PATHS,
    testing,
});

const checkTlsCertPathValidity =
    ({ cert_path: certPath, cert_key_path: certKeyPath }, callback) => {

        return dispatch => {

            dispatch(testingTlsCertPaths(false));
            dispatch(setTlsCerts(certPath.absolute_path, certKeyPath.absolute_path))
            dispatch(setCertPathValidity({ certPath, certKeyPath }));

            if (!certPath.invalid && !certKeyPath.invalid) {

                dispatch(advanceUI());
                callback();

            };

        };

    };

export const uploadTlsCertFiles = (tlsCertFile, tlsCertKeyFile) =>

    dispatch => {

        dispatch(setTlsCertFiles(tlsCertFile, tlsCertKeyFile));
        dispatch(uploadingTlsCertFiles(true));
        postCerts(tlsCertFile, tlsCertKeyFile)
            .then(
                result => {

                    dispatch(uploadingTlsCertFiles(false));
                    dispatch(advanceUI())

                },
                error => dispatch(fail(error)),
            )

    };

const uploadingTlsCertFiles = uploading => ({
    type: UPLOADING_TLS_CERT_PATHS,
    uploading,
});

export const setTlsCertFiles = (tlsCertFile, tlsCertKeyFile) => ({
    type: SET_TLS_CERT_FILES,
    tlsCertFile,
    tlsCertKeyFile,
})

const setCertPathValidity = ({ certPath, certKeyPath }) => ({
    type: SET_TLS_CERT_PATHS_VALIDITY,
    certPathInvalid: certPath.invalid,
    certKeyPathInvalid: certKeyPath.invalid,
});

export const gettingSecretKeys = () => ({
    type: GETTING_SECRET_KEY,
});

export const getSecretKey = serverName => {

    return dispatch => {

        getSecretkey(serverName).then(
            result => dispatch(setSecretKey(result)),
            error => dispatch(fail(error)),
        )

    };

};

export const setSecretKey = key => ({
    type: SET_SECRET_KEY,
    key,
});

export const start = setupDone => ({
    type: BASE_CONFIG_CHECKED,
    setupDone,
});

export const fail = reason => ({
    type: FAIL,
    reason,
});

export const advanceUI = option => ({
    type: ADVANCE_UI,
    option,
});

export const setServername = servername => ({
    type: SET_SERVERNAME,
    servername,
});

export const setStats = consent => ({
    type: SET_STATS,
    consent,
});

export const setDelegation = delegationType => ({
    type: SET_DELEGATION,
    delegationType,
});

export const setDelegationServername = servername => ({
    type: SET_DELEGATION_SERVERNAME,
    servername,
});

export const setDelegationPorts = (federationPort, clientPort) => ({
    type: SET_DELEGATION_PORTS,
    federationPort,
    clientPort,
});

export const setReverseProxy = proxyType => ({
    type: SET_REVERSE_PROXY,
    proxyType,
});

export const setTls = tlsType => ({
    type: SET_TLS,
    tlsType,
});

export const setSynapsePorts = (federationPort, clientPort, callback) => {

    const fedPortPriv = federationPort < 1024;
    const clientPortPriv = clientPort < 1024;

    return dispatch => {

        dispatch(testingSynapsePorts(true));
        dispatch({
            type: SET_SYNAPSE_PORTS,
            federationPort,
            clientPort,
        })
        testPorts([federationPort, clientPort])
            .then(
                results => dispatch(updatePortsFree(
                    fedPortPriv ? true : results.ports[0],
                    clientPortPriv ? true : results.ports[1],
                    callback,
                )),
                error => dispatch(fail(error)),
            )

    }

};

export const updatePortsFree =
    (synapseFederationPortFree, synapseClientPortFree, callback) => {

        return dispatch => {

            dispatch(testingSynapsePorts(false));
            dispatch({
                type: SET_SYNAPSE_PORTS_FREE,
                synapseFederationPortFree,
                synapseClientPortFree,
            });
            if (synapseFederationPortFree && synapseClientPortFree) {

                callback();
                dispatch(advanceUI());

            }

        }

    }

export const testingSynapsePorts = verifying => ({
    type: TESTING_SYNAPSE_PORTS,
    verifying,
})

export const setDatabase = databaseConfig => ({
    type: SET_DATABASE,
    databaseConfig,
})

export const writeConfig = (callback) => {

    return (dispatch, getState) => {

        postConfig(baseConfigToSynapseConfig(getState().baseConfig))
            .then(
                res => startSynapse().then(
                    res => {
                        if (Response.ok) {

                            dispatch(advanceUI());
                            callback();

                        } else {
                            dispatch(synapseStartFailed());
                        }
                    },
                    error => {

                        fail(error);
                        dispatch(synapseStartFailed());

                    }
                ),
                error => {

                    dispatch(fail(error));
                    dispatch(synapseStartStartFailed())

                }
            )

    }

}

export const synapseStartFailed = () => ({
    type: SYNAPSE_START_FAILED,
})

export const resetUI = (ui) => ({
    type: BACK_UI,
    ui,
})