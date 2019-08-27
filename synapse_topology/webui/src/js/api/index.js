import fetchAbsolute from 'fetch-absolute';
import {
    API_URL,
    CONFIG,
    SECRET_KEY,
    SERVER_NAME,
    SETUP_CHECK,
    CERT_PATHS,
    TEST_PORTS,
    START,
} from './constants';

const fetchAbs = fetchAbsolute(fetch)(API_URL)

export const getServerName = () =>
    fetchAbs(SERVER_NAME)
        .then(res => res.json())


export const postCertPaths = (certPath, certKeyPath) =>
    fetchAbs(
        CERT_PATHS,
        {
            method: 'POST',
            body: JSON.stringify({
                // eslint-disable-next-line camelcase
                cert_path: certPath,
                // eslint-disable-next-line camelcase
                cert_key_path: certKeyPath,
            }),
        },
    ).then(res => res.json())

export const postCerts = (cert, certKey) =>
    fetchAbs(
        CERT_PATHS,
        {
            method: 'POST',
            body: JSON.stringify({
                cert,
                // eslint-disable-next-line camelcase
                cert_key: certKey,
            }),
        },
    )

export const testPorts = (ports) =>
    fetchAbs(
        TEST_PORTS,
        {
            method: 'POST',
            body: JSON.stringify({
                ports,
            }),
        },
    ).then(res => res.json())

export const getSecretkey = serverName =>
    fetchAbs(
        SECRET_KEY,
        {
            method: 'POST',
            body: JSON.stringify({
                server_name: serverName,
            })
        }
    )
        .then(res => res.json())
        .then(json => json.secret_key)

export const getConfig = () => {

};

export const postConfig = (config, subConfigName) =>
    fetchAbs(
        subConfigName ? CONFIG + "/" + subConfigName : CONFIG,
        {
            method: 'POST',
            body: JSON.stringify(config),
        },
    );


// Checks if the server's base config has been setup.
export const getServerSetup = () => fetchAbs(SETUP_CHECK)
    .then(res => res.json())

export const startSynapse = () => fetchAbs(
    START,
    {
        method: 'POST',
    }
)