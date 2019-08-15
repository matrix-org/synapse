import React from 'react';
export default ({
  delegationFedPort,
  delegationClientPort,
  fedPort,
  clientPort,
  synapseServerName,
}) => `listen {delegationClientPort} ssl;
listen [::]:${delegationClientPort} ssl;
server_name ${synapseServerName};

  location /_matrix {
    proxy_pass http://localhost:${clientPort};
    proxy_set_header X-Forwarded-For $remote_addr;
  }
}

server {
  listen ${delegationFedPort} ssl default_server;
  listen [::]:${delegationFedPort} ssl default_server;
  server_name ${synapseServerName};

  location / {
    proxy_pass http://localhost:${fedPort};
    proxy_set_header X-Forwarded-For $remote_addr;
  }
}`