/* eslint-disable max-len */
export default ({
    synapseServerName,
    delegationClientPort,
}) => `{
  "m.homeserver": {
    "base_url": "https://${synapseServerName}${delegationClientPort ? `:${delegationClientPort}` : ""}"
  },
}`
// TODO: Maybe include this?
// "m.identity_server": {
//   "base_url": "https://identity.example.com"
// },