export default ({
    synapseServerName,
    delegationSynapsePort,
}) => `{
  "m.server": "${synapseServerName}:${delegationSynapsePort}"
}`