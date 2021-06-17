# Using a reverse proxy with Synapse

It is recommended to put a reverse proxy such as
[nginx](https://nginx.org/en/docs/http/ngx_http_proxy_module.html),
[Apache](https://httpd.apache.org/docs/current/mod/mod_proxy_http.html),
[Caddy](https://caddyserver.com/docs/quick-starts/reverse-proxy),
[HAProxy](https://www.haproxy.org/) or
[relayd](https://man.openbsd.org/relayd.8) in front of Synapse. One advantage
of doing so is that it means that you can expose the default https port
(443) to Matrix clients without needing to run Synapse with root
privileges.

You should configure your reverse proxy to forward requests to `/_matrix` or
`/_synapse/client` to Synapse, and have it set the `X-Forwarded-For` and
`X-Forwarded-Proto` request headers.

You should remember that Matrix clients and other Matrix servers do not
necessarily need to connect to your server via the same server name or
port. Indeed, clients will use port 443 by default, whereas servers default to
port 8448. Where these are different, we refer to the 'client port' and the
'federation port'. See [the Matrix
specification](https://matrix.org/docs/spec/server_server/latest#resolving-server-names)
for more details of the algorithm used for federation connections, and
[delegate.md](delegate.md) for instructions on setting up delegation.

**NOTE**: Your reverse proxy must not `canonicalise` or `normalise`
the requested URI in any way (for example, by decoding `%xx` escapes).
Beware that Apache *will* canonicalise URIs unless you specify
`nocanon`.

Let's assume that we expect clients to connect to our server at
`https://matrix.example.com`, and other servers to connect at
`https://example.com:8448`.  The following sections detail the configuration of
the reverse proxy and the homeserver.

## Reverse-proxy configuration examples

**NOTE**: You only need one of these.

### nginx

```
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    # For the federation port
    listen 8448 ssl http2 default_server;
    listen [::]:8448 ssl http2 default_server;

    server_name matrix.example.com;

    location ~* ^(\/_matrix|\/_synapse\/client) {
        proxy_pass http://localhost:8008;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;

        # Nginx by default only allows file uploads up to 1M in size
        # Increase client_max_body_size to match max_upload_size defined in homeserver.yaml
        client_max_body_size 50M;
    }
}
```

**NOTE**: Do not add a path after the port in `proxy_pass`, otherwise nginx will
canonicalise/normalise the URI.

### Caddy 1

```
matrix.example.com {
  proxy /_matrix http://localhost:8008 {
    transparent
  }

  proxy /_synapse/client http://localhost:8008 {
    transparent
  }
}

example.com:8448 {
  proxy / http://localhost:8008 {
    transparent
  }
}
```

### Caddy 2

```
matrix.example.com {
  reverse_proxy /_matrix/* http://localhost:8008
  reverse_proxy /_synapse/client/* http://localhost:8008
}

example.com:8448 {
  reverse_proxy http://localhost:8008
}
```

### Apache

```
<VirtualHost *:443>
    SSLEngine on
    ServerName matrix.example.com

    RequestHeader set "X-Forwarded-Proto" expr=%{REQUEST_SCHEME}
    AllowEncodedSlashes NoDecode
    ProxyPreserveHost on
    ProxyPass /_matrix http://127.0.0.1:8008/_matrix nocanon
    ProxyPassReverse /_matrix http://127.0.0.1:8008/_matrix
    ProxyPass /_synapse/client http://127.0.0.1:8008/_synapse/client nocanon
    ProxyPassReverse /_synapse/client http://127.0.0.1:8008/_synapse/client
</VirtualHost>

<VirtualHost *:8448>
    SSLEngine on
    ServerName example.com

    RequestHeader set "X-Forwarded-Proto" expr=%{REQUEST_SCHEME}
    AllowEncodedSlashes NoDecode
    ProxyPass /_matrix http://127.0.0.1:8008/_matrix nocanon
    ProxyPassReverse /_matrix http://127.0.0.1:8008/_matrix
</VirtualHost>
```

**NOTE**: ensure the  `nocanon` options are included.

**NOTE 2**: It appears that Synapse is currently incompatible with the ModSecurity module for Apache (`mod_security2`). If you need it enabled for other services on your web server, you can disable it for Synapse's two VirtualHosts by including the following lines before each of the two `</VirtualHost>` above:

```
<IfModule security2_module>
    SecRuleEngine off
</IfModule>
```

**NOTE 3**: Missing `ProxyPreserveHost on` can lead to a redirect loop.

### HAProxy

```
frontend https
  bind :::443 v4v6 ssl crt /etc/ssl/haproxy/ strict-sni alpn h2,http/1.1
  http-request set-header X-Forwarded-Proto https if { ssl_fc }
  http-request set-header X-Forwarded-Proto http if !{ ssl_fc }
  http-request set-header X-Forwarded-For %[src]

  # Matrix client traffic
  acl matrix-host hdr(host) -i matrix.example.com
  acl matrix-path path_beg /_matrix
  acl matrix-path path_beg /_synapse/client

  use_backend matrix if matrix-host matrix-path

frontend matrix-federation
  bind :::8448 v4v6 ssl crt /etc/ssl/haproxy/synapse.pem alpn h2,http/1.1
  http-request set-header X-Forwarded-Proto https if { ssl_fc }
  http-request set-header X-Forwarded-Proto http if !{ ssl_fc }
  http-request set-header X-Forwarded-For %[src]

  default_backend matrix

backend matrix
  server matrix 127.0.0.1:8008
```

### Relayd

```
table <webserver>    { 127.0.0.1 }
table <matrixserver> { 127.0.0.1 }

http protocol "https" {
    tls { no tlsv1.0, ciphers "HIGH" }
    tls keypair "example.com"
    match header set "X-Forwarded-For"   value "$REMOTE_ADDR"
    match header set "X-Forwarded-Proto" value "https"

    # set CORS header for .well-known/matrix/server, .well-known/matrix/client
    # httpd does not support setting headers, so do it here
    match request path "/.well-known/matrix/*" tag "matrix-cors"
    match response tagged "matrix-cors" header set "Access-Control-Allow-Origin" value "*"

    pass quick path "/_matrix/*"         forward to <matrixserver>
    pass quick path "/_synapse/client/*" forward to <matrixserver>

    # pass on non-matrix traffic to webserver
    pass                                 forward to <webserver>
}

relay "https_traffic" {
    listen on egress port 443 tls
    protocol "https"
    forward to <matrixserver> port 8008 check tcp
    forward to <webserver>    port 8080 check tcp
}

http protocol "matrix" {
    tls { no tlsv1.0, ciphers "HIGH" }
    tls keypair "example.com"
    block
    pass quick path "/_matrix/*"         forward to <matrixserver>
    pass quick path "/_synapse/client/*" forward to <matrixserver>
}

relay "matrix_federation" {
    listen on egress port 8448 tls
    protocol "matrix"
    forward to <matrixserver> port 8008 check tcp
}
```

## Homeserver Configuration

You will also want to set `bind_addresses: ['127.0.0.1']` and
`x_forwarded: true` for port 8008 in `homeserver.yaml` to ensure that
client IP addresses are recorded correctly.

Having done so, you can then use `https://matrix.example.com` (instead
of `https://matrix.example.com:8448`) as the "Custom server" when
connecting to Synapse from a client.


## Health check endpoint

Synapse exposes a health check endpoint for use by reverse proxies.
Each configured HTTP listener has a `/health` endpoint which always returns
200 OK (and doesn't get logged).

## Synapse administration endpoints

Endpoints for administering your Synapse instance are placed under
`/_synapse/admin`. These require authentication through an access token of an
admin user. However as access to these endpoints grants the caller a lot of power,
we do not recommend exposing them to the public internet without good reason.
