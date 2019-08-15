/* eslint-disable max-len */
export default ({
    delegationFedPort,
    delegationClientPort,
    fedPort,
    clientPort,
    synapseServerName,
}) => {

    if (fedPort == clientPort) {

        return `frontend https
  bind :::${delegationClientPort} v4v6 ssl crt /etc/ssl/haproxy/ strict-sni alpn h2,http/1.1

  # Matrix client traffic
  acl matrix-host hdr(host) -i ${synapseServerName}
  acl matrix-path path_beg /_matrix

  use_backend matrix if matrix-host matrix-path

frontend matrix-federation
  bind :::${delegationFedPort} v4v6 ssl crt /etc/ssl/haproxy/<your_tls_cert>.pem alpn h2,http/1.1
  default_backend matrix

backend matrix
  server matrix 127.0.0.1:${fedPort}
`

    } else {

        return `frontend https
  bind:::${delegationClientPort} v4v6 ssl crt /etc/ssl/haproxy/ strict-sni alpn h2, http / 1.1

# Matrix client traffic
acl matrix-host hdr(host) -i ${synapseServerName}
acl matrix-path path_beg /_matrix

use_backend matrix-client if matrix-host matrix-path

frontend matrix - federation
bind::: ${delegationFedPort} v4v6 ssl crt /etc/ssl/haproxy/<your_tls_cert>.pem alpn h2,http/1.1
default_backend matrix

backend matrix
  server matrix 127.0.0.1:${fedPort}

backend matrix-client 127.0.0.1:${clientPort}`

    }

}