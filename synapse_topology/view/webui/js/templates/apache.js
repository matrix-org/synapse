export default ({
  delegationFedPort,
  delegationClientPort,
  fedPort,
  clientPort,
  synapseServerName,
}) => `
<VirtualHost *:${delegationClientPort}>
    SSLEngine on
    ServerName ${synapseServerName};

    AllowEncodedSlashes NoDecode
    ProxyPass /_matrix http://127.0.0.1:${clientPort}/_matrix nocanon
    ProxyPassReverse /_matrix http://127.0.0.1:${clientPort}/_matrix
</VirtualHost>

<VirtualHost *:${delegationFedPort}>
    SSLEngine on
    ServerName ${synapseServerName};

    AllowEncodedSlashes NoDecode
    ProxyPass /_matrix http://127.0.0.1:${fedPort}/_matrix nocanon
    ProxyPassReverse /_matrix http://127.0.0.1:${fedPort}/_matrix
</VirtualHost>
`