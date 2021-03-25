Setting up federation
=====================

Federation is the process by which users on different servers can participate
in the same room. For this to work, those other servers must be able to contact
yours to send messages.

The `server_name` configured in the Synapse configuration file (often
`homeserver.yaml`) defines how resources (users, rooms, etc.) will be
identified (eg: `@user:example.com`, `#room:example.com`). By default,
it is also the domain that other servers will use to try to reach your
server (via port 8448). This is easy to set up and will work provided
you set the `server_name` to match your machine's public DNS hostname.

For this default configuration to work, you will need to listen for TLS
connections on port 8448. The preferred way to do that is by using a
reverse proxy: see [reverse_proxy.md](<reverse_proxy.md>) for instructions
on how to correctly set one up.

In some cases you might not want to run Synapse on the machine that has
the `server_name` as its public DNS hostname, or you might want federation
traffic to use a different port than 8448. For example, you might want to
have your user names look like `@user:example.com`, but you want to run
Synapse on `synapse.example.com` on port 443. This can be done using
delegation, which allows an admin to control where federation traffic should
be sent. See [delegate.md](delegate.md) for instructions on how to set this up.

Once federation has been configured, you should be able to join a room over
federation. A good place to start is `#synapse:matrix.org` - a room for
Synapse admins.

## Troubleshooting

You can use the [federation tester](https://matrix.org/federationtester)
to check if your homeserver is configured correctly. Alternatively try the
[JSON API used by the federation tester](https://matrix.org/federationtester/api/report?server_name=DOMAIN).
Note that you'll have to modify this URL to replace `DOMAIN` with your
`server_name`. Hitting the API directly provides extra detail.

The typical failure mode for federation is that when the server tries to join
a room, it is rejected with "401: Unauthorized". Generally this means that other
servers in the room could not access yours. (Joining a room over federation is
a complicated dance which requires connections in both directions).

Another common problem is that people on other servers can't join rooms that
you invite them to. This can be caused by an incorrectly-configured reverse
proxy: see [reverse_proxy.md](<reverse_proxy.md>) for instructions on how to correctly
configure a reverse proxy.

### Known issues

**HTTP `308 Permanent Redirect` redirects are not followed**: Due to missing features
in the HTTP library used by Synapse, 308 redirects are currently not followed by
federating servers, which can cause `M_UNKNOWN` or `401 Unauthorized` errors. This
may affect users who are redirecting apex-to-www (e.g. `example.com` -> `www.example.com`),
and especially users of the Kubernetes *Nginx Ingress* module, which uses 308 redirect
codes by default. For those Kubernetes users, [this Stackoverflow post](https://stackoverflow.com/a/52617528/5096871) 
might be helpful. For other users, switching to a `301 Moved Permanently` code may be
an option. 308 redirect codes will be supported properly in a future
release of Synapse.

## Running a demo federation of Synapses

If you want to get up and running quickly with a trio of homeservers in a
private federation, there is a script in the `demo` directory. This is mainly
useful just for development purposes. See [demo/README](<../demo/README>).
