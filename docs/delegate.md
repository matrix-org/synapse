# Delegation

For a more flexible configuration, you can have `server_name`
resources (eg: `@user:example.com`) served by a different host and
port (eg: `synapse.example.com:443`).

Without configuring delegation, the matrix federation will
expect to find your server via `example.com:8448`. The following methods
allow you retain a `server_name` of `example.com` so that your user IDs, room
aliases, etc continue to look like `*:example.com`, whilst having your
federation traffic routed to a different server (e.g. `synapse.example.com`).

## .well-known delegation

To use this method, you need to be able to alter the
`server_name` 's https server to serve the `/.well-known/matrix/server`
URL. Having an active server (with a valid TLS certificate) serving your
`server_name` domain is out of the scope of this documentation.

The URL `https://<server_name>/.well-known/matrix/server` should
return a JSON structure containing the key `m.server` like so:

```json
{
    "m.server": "<synapse.server.name>[:<yourport>]"
}
```

In our example, this would mean that URL `https://example.com/.well-known/matrix/server`
should return:

```json
{
    "m.server": "synapse.example.com:443"
}
```

Note, specifying a port is optional. If no port is specified, then it defaults
to 8448.

Most installations will not need to configure .well-known. However, it can be
useful in cases where the admin is hosting on behalf of someone else and
therefore cannot gain access to the necessary certificate. With .well-known,
federation servers will check for a valid TLS certificate for the delegated
hostname (in our example: `synapse.example.com`).

## Delegation FAQ

### When do I need delegation?

If your homeserver's APIs are accessible on the default federation port (8448)
and the domain your `server_name` points to, you do not need any delegation.

For instance, if you registered `example.com` and pointed its DNS A record at a
fresh server, you could install Synapse on that host, giving it a `server_name`
of `example.com`, and once a reverse proxy has been set up to proxy all requests
sent to the port `8448` and serve TLS certificates for `example.com`, you
wouldn't need any delegation set up.

**However**, if your homeserver's APIs aren't accessible on port 8448 and on the
domain `server_name` points to, you will need to let other servers know how to
find it using delegation.

### Do you still recommend against using a reverse proxy on the federation port?

We no longer actively recommend against using a reverse proxy. Many admins will
find it easier to direct federation traffic to a reverse proxy and manage their
own TLS certificates, and this is a supported configuration.

See [reverse_proxy.md](reverse_proxy.md) for information on setting up a
reverse proxy.

### Do I still need to give my TLS certificates to Synapse if I am using a reverse proxy?

This is no longer necessary. If you are using a reverse proxy for all of your
TLS traffic, then you can set `no_tls: True` in the Synapse config.

In that case, the only reason Synapse needs the certificate is to populate a legacy
`tls_fingerprints` field in the federation API. This is ignored by Synapse 0.99.0
and later, and the only time pre-0.99 Synapses will check it is when attempting to
fetch the server keys - and generally this is delegated via `matrix.org`, which
is running a modern version of Synapse.

### Do I need the same certificate for the client and federation port?

No. There is nothing stopping you from using different certificates,
particularly if you are using a reverse proxy.