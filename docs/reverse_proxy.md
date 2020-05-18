# Using a reverse proxy with Synapse

It is recommended to put a reverse proxy such as
[nginx](https://nginx.org/en/docs/http/ngx_http_proxy_module.html),
[Apache](https://httpd.apache.org/docs/current/mod/mod_proxy_http.html),
[Caddy](https://caddyserver.com/docs/proxy) or
[HAProxy](https://www.haproxy.org/) in front of Synapse. One advantage
of doing so is that it means that you can expose the default https port
(443) to Matrix clients without needing to run Synapse with root
privileges.

**NOTE**: Your reverse proxy must not `canonicalise` or `normalise`
the requested URI in any way (for example, by decoding `%xx` escapes).
Beware that Apache *will* canonicalise URIs unless you specifify
`nocanon`.

When setting up a reverse proxy, remember that Matrix clients and other
Matrix servers do not necessarily need to connect to your server via the
same server name or port. Indeed, clients will use port 443 by default,
whereas servers default to port 8448. Where these are different, we
refer to the 'client port' and the 'federation port'. See [the Matrix
specification](https://matrix.org/docs/spec/server_server/latest#resolving-server-names)
for more details of the algorithm used for federation connections, and
[delegate.md](<delegate.md>) for instructions on setting up delegation.

Let's assume that we expect clients to connect to our server at
`https://matrix.example.com`, and other servers to connect at
`https://example.com:8448`.  The following sections detail the configuration of
the reverse proxy and the homeserver.

## Reverse-proxy configuration examples

**NOTE**: You only need one of these.

### nginx

```
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name matrix.example.com;

    location /_matrix {
        proxy_pass http://localhost:8008;
        proxy_set_header X-Forwarded-For $remote_addr;
        # Nginx by default only allows file uploads up to 1M in size
        # Increase client_max_body_size to match max_upload_size defined in homeserver.yaml
        client_max_body_size 10M;
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
```

**NOTE**: Do not add a path after the port in `proxy_pass`, otherwise nginx will
canonicalise/normalise the URI.

### Caddy 1

```
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
```

### Caddy 2

```
matrix.example.com {
  reverse_proxy /_matrix/* http://localhost:8008
}

example.com:8448 {
  reverse_proxy http://localhost:8008
}
```

### Apache

```
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
```

**NOTE**: ensure the  `nocanon` options are included.

### HAProxy

```
frontend https
  bind :::443 v4v6 ssl crt /etc/ssl/haproxy/ strict-sni alpn h2,http/1.1

  # Matrix client traffic
  acl matrix-host hdr(host) -i matrix.example.com
  acl matrix-path path_beg /_matrix

  use_backend matrix if matrix-host matrix-path

frontend matrix-federation
  bind :::8448 v4v6 ssl crt /etc/ssl/haproxy/synapse.pem alpn h2,http/1.1
  default_backend matrix

backend matrix
  server matrix 127.0.0.1:8008
```

## Homeserver Configuration

You will also want to set `bind_addresses: ['127.0.0.1']` and
`x_forwarded: true` for port 8008 in `homeserver.yaml` to ensure that
client IP addresses are recorded correctly.

Having done so, you can then use `https://matrix.example.com` (instead
of `https://matrix.example.com:8448`) as the "Custom server" when
connecting to Synapse from a client.
