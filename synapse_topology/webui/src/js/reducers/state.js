import {
    SERVER_NAME_UI,
    STATS_REPORT_UI,
    KEY_EXPORT_UI,
    DELEGATION_OPTIONS_UI,
    PORT_SELECTION_UI,
    DATABASE_UI,
    COMPLETE_UI,
    TLS_UI,
} from './ui-constants';

const setupUI = "setupUI";
const activeBlocks = "activeBlocks";
const configUI = "configUI";
const baseConfig = "baseConfig";
const setupDone = "setupDone";
const baseConfigChecked = "baseConfigChecked";
const servername = "servername";
const reportStats = "reportStats";
const gettingSecretKey = "gettingSecretKey";
const secretKey = "secretKey";
const delegationType = "delegationType";
const delegationServerName = "delegationServerName";
const delegationFederationPort = "delegationFederationPort";
const delegationClientPort = "delegationClientPort";
const reverseProxy = "reverseProxy";
const tls = "tls";
const testingCertPaths = "testingCertPaths";
const uploadingCerts = "uploadingCerts";
const certPathInvalid = "certPathInvalid";
const certKeyPathInvalid = "certKeyPathInvalid";
const tlsCertPath = "tlsCertPath";
const tlsCertKeyPath = "tlsCertKeyPath";
const tlsCertFile = "tlsCertFile";
const tlsCertKeyFile = "tlsCertKeyFile";
const tlsPath = "tlsPath";
const verifyingPorts = "verifyingPorts";
const synapseFederationPortFree = "synapseFederationPortFree";
const synapseClientPortFree = "synapseClientPortFree";
const synapseFederationPort = "synapseFederationPort";
const synapseClientPort = "synapseClientPort";
const database = "database";
const configDir = "configDir";

const state = {
    [setupUI]: {
        [activeBlocks]: ["block1"],
    },
    [configUI]: {

    },
    [baseConfig]: {
        [setupDone]: true,
        [baseConfigChecked]: false,
        [configDir]: "sadfasdf",
        [servername]: "server_name",
        [reportStats]: false,
        [gettingSecretKey]: false,
        [secretKey]: "asdfsadf",
        [delegationType]: "local|well_known|DNS_SRV",
        [delegationServerName]: "name",
        [delegationFederationPort]: "\"\"|325",
        [delegationClientPort]: "\"\"|325",
        [reverseProxy]: "nginx|caddy|apache|haproxy|other|none",
        [tls]: "acme|tls|reverseproxy",
        [testingCertPaths]: true,
        [uploadingCerts]: true,
        [certPathInvalid]: true,
        [certKeyPathInvalid]: true,
        [tlsCertPath]: "sadfaf",
        [tlsCertKeyPath]: "sdfasdf",
        [tlsCertFile]: "sadfa;dlf;sad;fkla;sdlfjkas;dlfkjas;dflkja;sdfkljadf ------",
        [tlsCertKeyFile]: "sadfa;dlf;sad;fkla;sdlfjkas;dlfkjas;dflkja;sdfkljadf ------",
        [verifyingPorts]: true,
        [synapseFederationPortFree]: true,
        [synapseClientPortFree]: true,
        [synapseFederationPort]: 1234,
        [synapseClientPort]: 1234,
        [database]: "sqlite3|postgres",
    },
}

export const uiStateMapping = {
    base: [
        setupDone,
        baseConfigChecked,
        configDir,
    ],
    [SERVER_NAME_UI]: [
        servername,
    ],
    [STATS_REPORT_UI]: [
        reportStats,
    ],
    [KEY_EXPORT_UI]: [
        gettingSecretKey,
        secretKey,
    ],
    [DELEGATION_OPTIONS_UI]: [
        delegationType,
        delegationServerName,
        delegationClientPort,
        delegationFederationPort,
    ],
    [TLS_UI]: [
        tls,
        reverseProxy,
        testingCertPaths,
        uploadingCerts,
        certPathInvalid,
        certKeyPathInvalid,
        tlsCertPath,
        tlsCertKeyPath,
        tlsCertFile,
        tlsCertKeyFile,
    ],
    [PORT_SELECTION_UI]: [
        verifyingPorts,
        synapseClientPort,
        synapseFederationPort,
        synapseClientPortFree,
        synapseFederationPortFree,
    ],
    [DATABASE_UI]: [
        database,
    ],
    [COMPLETE_UI]: [
    ],
}