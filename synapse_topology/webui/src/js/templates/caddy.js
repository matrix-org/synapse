export default ({
    delegationFedPort,
    delegationClientPort,
    fedPort,
    clientPort,
    synapseServerName,
}) => `${synapseServerName}:${delegationClientPort} {
  proxy /_matrix http://localhost:${clientPort} {
    transparent
  }
}

${synapseServerName}:${delegationFedPort} {
  proxy / http://localhost:${fedPort} {
    transparent
  }
}`