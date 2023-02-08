# Delegation of incoming federation traffic

In the following documentation, we use the term `server_name` to refer to that setting
in your homeserver configuration file. It appears at the ends of user ids, and tells
other homeservers where they can find your server.

By default, other homeservers will expect to be able to reach yours via
your `server_name`, on port 8448. For example, if you set your `server_name`
to `example.com` (so that your user names look like `@user:example.com`),
other servers will try to connect to yours at `https://example.com:8448/`.

Delegation is a Matrix feature allowing a homeserver admin to retain a
`server_name` of `example.com` so that user IDs, room aliases, etc continue
to look like `*:example.com`, whilst having federation traffic routed
to a different server and/or port (e.g. `synapse.example.com:443`).

## .well-known delegation

To use this method, you need to be able to configure the server at
`https://<server_name>` to serve a file at
`https://<server_name>/.well-known/matrix/server`.  There are two ways to do this, shown below.

Note that the `.well-known` file is hosted on the default port for `https` (port 443).

### External server

For maximum flexibility, you need to configure an external server such as nginx, Apache
or HAProxy to serve the `https://<server_name>/.well-known/matrix/server` file. Setting
up such a server is out of the scope of this documentation, but note that it is often
possible to configure your [reverse proxy](reverse_proxy.md) for this.

The URL `https://<server_name>/.well-known/matrix/server` should be configured
return a JSON structure containing the key `m.server` like this:

```json
{
    "m.server": "<synapse.server.name>[:<yourport>]"
}
```

In our example (where we want federation traffic to be routed to
`https://synapse.example.com`, on port 443), this would mean that
`https://example.com/.well-known/matrix/server` should return:

```json
{
    "m.server": "synapse.example.com:443"
}
```

Note, specifying a port is optional. If no port is specified, then it defaults
to 8448.

### Serving a `.well-known/matrix/server` file with Synapse

If you are able to set up your domain so that `https://<server_name>` is routed to
Synapse (i.e., the only change needed is to direct federation traffic to port 443
instead of port 8448), then it is possible to configure Synapse to serve a suitable
`.well-known/matrix/server` file. To do so, add the following to your `homeserver.yaml`
file:

```yaml
serve_server_wellknown: true
```

**Note**: this *only* works if `https://<server_name>` is routed to Synapse, so is
generally not suitable if Synapse is hosted at a subdomain such as
`https://synapse.example.com`.

## SRV DNS record delegation

It is also possible to do delegation using a SRV DNS record. However, that is generally
not recommended, as it can be difficult to configure the TLS certificates correctly in
this case, and it offers little advantage over `.well-known` delegation.

Please keep in mind that server delegation is a function of server-server communication,
and as such using SRV DNS records will not cover use cases involving client-server comms.
This means setting global client settings (such as a Jitsi endpoint, or disabling
creating new rooms as encrypted by default, etc) will still require that you serve a file
from the `https://<server_name>/.well-known/` endpoints defined in the spec! If you are
considering using SRV DNS delegation to avoid serving files from this endpoint, consider
the impact that you will not be able to change those client-based default values globally,
and will be relegated to the featureset of the configuration of each individual client.

However, if you really need it, you can find some documentation on what such a
record should look like and how Synapse will use it in [the Matrix
specification](https://matrix.org/docs/spec/server_server/latest#resolving-server-names).

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

### Should I use a reverse proxy for federation traffic?

Generally, using a reverse proxy for both the federation and client traffic is a good
idea, since it saves handling TLS traffic in Synapse. See
[the reverse proxy documentation](reverse_proxy.md) for information on setting up a
reverse proxy.
