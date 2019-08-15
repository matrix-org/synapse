/* eslint-disable max-len */
export default ({
    delegationFedPort,
    delegationClientPort,
    fedPort,
    clientPort,
    serverName,
    synapseServerName,
}) => `_matrix._tcp.${serverName} 3600 IN SRV 10 5 ${delegationClientPort} ${synapseServerName}`