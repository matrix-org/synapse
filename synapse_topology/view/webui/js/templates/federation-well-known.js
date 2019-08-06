export const config = (
  synapseServerName,
  delegationSynapsePort,
) => `
{
  "m.server": "${synapseServerName}:${delegationSynapsePort}"
}
`