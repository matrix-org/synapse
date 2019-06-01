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
          
          # add here your ssl config as desribed in
          # https://nginx.org/en/docs/http/configuring_https_servers.html
          server_name matrix.example.com;

          location /_matrix {
              proxy_set_header Host $host;
              # to be on the safe site if module real ip not available
              proxy_set_header X-Real-IP $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Port $server_port;
              proxy_set_header X-Forwarded-Proto $scheme;
              proxy_pass http://localhost:8008;
              proxy_set_header X-Forwarded-For $remote_addr;
          }
      }

      server {
          listen 8448 ssl default_server;
          listen [::]:8448 ssl default_server;
          
          # add here your ssl config as desribed in
          # https://nginx.org/en/docs/http/configuring_https_servers.html
          
          server_name example.com;

          location / {
              proxy_set_header Host $host;
              # to be on the safe site if module real ip not available
              proxy_set_header X-Real-IP $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Port $server_port;
              proxy_set_header X-Forwarded-Proto $scheme;
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

      global
        log stdout format raw daemon info
        tune.ssl.default-dh-param 3072
        
        # https://mozilla.github.io/server-side-tls/ssl-config-generator/?server=haproxy-1.8.0&openssl=1.1.0i&hsts=yes&profile=modern
        # set default parameters to the intermediate configuration
        ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
        ssl-default-bind-options ssl-min-ver TLSv1.1 no-tls-tickets

        ssl-default-server-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
        ssl-default-server-options ssl-min-ver TLSv1.1 no-tls-tickets
      
      #---------------------------------------------------------------------
      # common defaults that all the 'listen' and 'backend' sections will
      # use if not designated in their block
      #---------------------------------------------------------------------
      defaults
        mode                    tcp
        log                     global
        option                  dontlognull
        retries                 3
        timeout http-request    10s
        timeout queue           2m
        timeout connect         10s
        timeout client          5m
        timeout server          5m
        timeout http-keep-alive 10s
        timeout check           10s
        maxconn                 750
        
      frontend https
        bind :::443 v4v6 ssl crt /etc/ssl/haproxy/ strict-sni alpn h2,http/1.1

        mode http
        option dontlognull
        option forwardfor
        option http-ignore-probes
        # for haproxy 1.9 and upper can this be enabled
        # option http-use-htx
        
        # Strip off Proxy headers to prevent HTTpoxy (https://httpoxy.org/)
        http-request del-header Proxy

        http-request set-header Host %[req.hdr(host),lower]
        http-request set-header X-Forwarded-Proto https if { ssl_fc }
        http-request set-header X-Forwarded-Proto http  if !{ ssl_fc }
        http-request set-header X-Forwarded-Host %[req.hdr(host),lower]
        http-request set-header X-Forwarded-Port %[dst_port]
        http-request set-header X-Forwarded-Proto-Version h2 if { ssl_fc_alpn -i h2 }
   
        # Matrix client traffic
        acl matrix req.hdr(host) -i matrix.example.com
        use_backend matrix if matrix

      frontend matrix-federation
        bind :::8448 v4v6 ssl crt /etc/ssl/haproxy/synapse.pem alpn h2,http/1.1
        
        mode http
        option dontlognull
        option forwardfor
        option http-ignore-probes
        # for haproxy 1.9 and upper can this be enabled
        # option http-use-htx
        
        # Strip off Proxy headers to prevent HTTpoxy (https://httpoxy.org/)
        http-request del-header Proxy

        http-request set-header Host %[req.hdr(host),lower]
        http-request set-header X-Forwarded-Proto https if { ssl_fc }
        http-request set-header X-Forwarded-Proto http  if !{ ssl_fc }
        http-request set-header X-Forwarded-Host %[req.hdr(host),lower]
        http-request set-header X-Forwarded-Port %[dst_port]
        http-request set-header X-Forwarded-Proto-Version h2 if { ssl_fc_alpn -i h2 }
        
        default_backend matrix

      backend matrix
        server matrix 127.0.0.1:8008

You will also want to set ``bind_addresses: ['127.0.0.1']`` and ``x_forwarded: true``
for port 8008 in ``homeserver.yaml`` to ensure that client IP addresses are
recorded correctly.

Having done so, you can then use ``https://matrix.example.com`` (instead of
``https://matrix.example.com:8448``) as the "Custom server" when connecting to
Synapse from a client.
