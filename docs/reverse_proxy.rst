Using a reverse proxy with Synapse
==================================

It is recommended to put a reverse proxy such as
`nginx <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>`_,
`Apache <https://httpd.apache.org/docs/current/mod/mod_proxy_http.html>`_,
`Caddy <https://caddyserver.com/docs/proxy>`_ or
`HAProxy <https://www.haproxy.org/>`_ in front of Synapse. One advantage of
doing so is that it means that you can expose the default https port (443) to
Matrix clients without needing to run Synapse with root privileges.

**NOTE**: Your reverse proxy must not 'canonicalise' or 'normalise' the
requested URI in any way (for example, by decoding ``%xx`` escapes). Beware
that Apache *will* canonicalise URIs unless you specifify ``nocanon``.

When setting up a reverse proxy, remember that Matrix clients and other Matrix
servers do not necessarily need to connect to your server via the same server
name or port. Indeed, clients will use port 443 by default, whereas servers
default to port 8448. Where these are different, we refer to the 'client port'
and the 'federation port'. See `Setting up federation
<federate.md>`_ for more details of the algorithm used for
federation connections.

Let's assume that we expect clients to connect to our server at
``https://matrix.example.com``, and other servers to connect at
``https://example.com:8448``. Here are some example configurations:

* nginx::

      server {
          listen 443 ssl;
          listen [::]:443 ssl;
          server_name matrix.example.com;

          location /_matrix {
              proxy_pass http://localhost:8008;
              proxy_set_header X-Forwarded-For $remote_addr;
          }
      }

      server {
          listen 8448 ssl default_server;
          listen [::]:8448 ssl default_server;
          server_name example.com;

          location / {
              proxy_pass http://localhost:8008;
              proxy_set_header X-Forwarded-For $remote_addr;
          }
      }

* Caddy::

      matrix.example.com {
        proxy /_matrix http://localhost:8008 {
          transparent
        }
      }

      example.com:8448 {
        proxy / http://localhost:8008 {
          transparent
        }
      }

* Apache (note the ``nocanon`` options here!)::

      <VirtualHost *:443>
          SSLEngine on
          ServerName matrix.example.com;

          AllowEncodedSlashes NoDecode
          ProxyPass /_matrix http://127.0.0.1:8008/_matrix nocanon
          ProxyPassReverse /_matrix http://127.0.0.1:8008/_matrix
      </VirtualHost>

      <VirtualHost *:8448>
          SSLEngine on
          ServerName example.com;
          
          AllowEncodedSlashes NoDecode
          ProxyPass /_matrix http://127.0.0.1:8008/_matrix nocanon
          ProxyPassReverse /_matrix http://127.0.0.1:8008/_matrix
      </VirtualHost>

* HAProxy::

      frontend https
        bind :::443 v4v6 ssl crt /etc/ssl/haproxy/ strict-sni alpn h2,http/1.1

        # Matrix client traffic
        acl matrix hdr(host) -i matrix.example.com
        use_backend matrix if matrix

      frontend matrix-federation
        bind :::8448 v4v6 ssl crt /etc/ssl/haproxy/synapse.pem alpn h2,http/1.1
        default_backend matrix

      backend matrix
        server matrix 127.0.0.1:8008

You will also want to set ``bind_addresses: ['127.0.0.1']`` and ``x_forwarded: true``
for port 8008 in ``homeserver.yaml`` to ensure that client IP addresses are
recorded correctly.

Having done so, you can then use ``https://matrix.example.com`` (instead of
``https://matrix.example.com:8448``) as the "Custom server" when connecting to
Synapse from a client.
