Setting up Federation
=====================

Federation is the process by which users on different servers can participate
in the same room. For this to work, those other servers must be able to contact
yours to send messages.

The ``server_name`` configured in the Synapse configuration file (often
``homeserver.yaml``) defines how resources (users, rooms, etc.) will be
identified (eg: ``@user:example.com``, ``#room:example.com``). By
default, it is also the domain that other servers will use to
try to reach your server (via port 8448). This is easy to set
up and will work provided you set the ``server_name`` to match your
machine's public DNS hostname, and provide Synapse with a TLS certificate
which is valid for your ``server_name``.

Once federation has been configured, you should be able to join a room over
federation. A good place to start is ``#synapse:matrix.org`` - a room for
Synapse admins.


## Delegation

For a more flexible configuration, you can have ``server_name``
resources (eg: ``@user:example.com``) served by a different host and
port (eg: ``synapse.example.com:443``). There are two ways to do this:

- adding a ``/.well-known/matrix/server`` URL served on ``https://example.com``.
- adding a DNS ``SRV`` record in the DNS zone of domain
  ``example.com``.

Without configuring delegation, the matrix federation will
expect to find your server via ``example.com:8448``. The following methods
allow you retain a `server_name` of `example.com` so that your user IDs, room
aliases, etc continue to look like `*:example.com`, whilst having your
federation traffic routed to a different server.

### .well-known delegation

To use this method, you need to be able to alter the
``server_name`` 's https server to serve the ``/.well-known/matrix/server``
URL. Having an active server (with a valid TLS certificate) serving your
``server_name`` domain is out of the scope of this documentation.

The URL ``https://<server_name>/.well-known/matrix/server`` should
return a JSON structure containing the key ``m.server`` like so:

    {
	    "m.server": "<synapse.server.name>[:<yourport>]"
    }

In our example, this would mean that URL ``https://example.com/.well-known/matrix/server``
should return:

    {
	    "m.server": "synapse.example.com:443"
    }

Note, specifying a port is optional. If a port is not specified an SRV lookup
is performed, as described below. If the target of the
delegation does not have an SRV record, then the port defaults to 8448.

Most installations will not need to configure .well-known. However, it can be
useful in cases where the admin is hosting on behalf of someone else and
therefore cannot gain access to the necessary certificate. With .well-known,
federation servers will check for a valid TLS certificate for the delegated
hostname (in our example: ``synapse.example.com``).

.well-known support first appeared in Synapse v0.99.0. To federate with older
servers you may need to additionally configure SRV delegation. Alternatively,
encourage the server admin in question to upgrade :).

### DNS SRV delegation

To use this delegation method, you need to have write access to your
``server_name`` 's domain zone DNS records (in our example it would be
``example.com`` DNS zone).

This method requires the target server to provide a
valid TLS certificate for the original ``server_name``.

You need to add a SRV record in your ``server_name`` 's DNS zone with
this format:

     _matrix._tcp.<yourdomain.com> <ttl> IN SRV <priority> <weight> <port> <synapse.server.name>

In our example, we would need to add this SRV record in the
``example.com`` DNS zone:

     _matrix._tcp.example.com. 3600 IN SRV 10 5 443 synapse.example.com.

Once done and set up, you can check the DNS record with ``dig -t srv
_matrix._tcp.<server_name>``. In our example, we would expect this:

    $ dig -t srv _matrix._tcp.example.com
    _matrix._tcp.example.com. 3600    IN      SRV     10 0 443 synapse.example.com.

Note that the target of a SRV record cannot be an alias (CNAME record): it has to point
directly to the server hosting the synapse instance.

### Delegation FAQ
#### When do I need a SRV record or .well-known URI?

If your homeserver listens on the default federation port (8448), and your
`server_name` points to the host that your homeserver runs on, you do not need an SRV
record or `.well-known/matrix/server` URI.

For instance, if you registered `example.com` and pointed its DNS A record at a
fresh server, you could install Synapse on that host,
giving it a `server_name` of `example.com`, and once [ACME](acme.md) support is enabled,
it would automatically generate a valid TLS certificate for you via Let's Encrypt
and no SRV record or .well-known URI would be needed.

This is the common case, although you can add an SRV record or
`.well-known/matrix/server` URI for completeness if you wish.

**However**, if your server does not listen on port 8448, or if your `server_name`
does not point to the host that your homeserver runs on, you will need to let
other servers know how to find it. The way to do this is via .well-known or an
SRV record.

#### I have created a .well-known URI. Do I still need an SRV record?

As of Synapse 0.99, Synapse will first check for the existence of a .well-known
URI and follow any delegation it suggests. It will only then check for the
existence of an SRV record.

That means that the SRV record will often be redundant. However, you should
remember that there may still be older versions of Synapse in the federation
which do not understand .well-known URIs, so if you removed your SRV record
you would no longer be able to federate with them.

It is therefore best to leave the SRV record in place for now. Synapse 0.34 and
earlier will follow the SRV record (and not care about the invalid
certificate). Synapse 0.99 and later will follow the .well-known URI, with the
correct certificate chain.

#### Can I manage my own certificates rather than having Synapse renew certificates itself?

Yes, you are welcome to manage your certificates yourself. Synapse will only
attempt to obtain certificates from Let's Encrypt if you configure it to do
so.The only requirement is that there is a valid TLS cert present for
federation end points.

#### Do you still recommend against using a reverse proxy on the federation port?

We no longer actively recommend against using a reverse proxy. Many admins will
find it easier to direct federation traffic to a reverse proxy and manage their
own TLS certificates, and this is a supported configuration.

See [reverse_proxy.rst](reverse_proxy.rst) for information on setting up a
reverse proxy.

#### Do I still need to give my TLS certificates to Synapse if I am using a reverse proxy?

Practically speaking, this is no longer necessary.

If you are using a reverse proxy for all of your TLS traffic, then you can set
`no_tls: True` in the Synapse config. In that case, the only reason Synapse
needs the certificate is to populate a legacy `tls_fingerprints` field in the
federation API. This is ignored by Synapse 0.99.0 and later, and the only time
pre-0.99 Synapses will check it is when attempting to fetch the server keys -
and generally this is delegated via `matrix.org`, which will be running a modern
version of Synapse.

#### Do I need the same certificate for the client and federation port?

No. There is nothing stopping you from using different certificates,
particularly if you are using a reverse proxy. However, Synapse will use the
same certificate on any ports where TLS is configured.

## Troubleshooting

You can use the [federation tester](
<https://matrix.org/federationtester>) to check if your homeserver is
configured correctly. Alternatively try the [JSON API used by the federation tester](https://matrix.org/federationtester/api/report?server_name=DOMAIN).
Note that you'll have to modify this URL to replace ``DOMAIN`` with your
``server_name``. Hitting the API directly provides extra detail.

The typical failure mode for federation is that when the server tries to join
a room, it is rejected with "401: Unauthorized". Generally this means that other
servers in the room could not access yours. (Joining a room over federation is
a complicated dance which requires connections in both directions).

Another common problem is that people on other servers can't join rooms that
you invite them to. This can be caused by an incorrectly-configured reverse
proxy: see [reverse_proxy.rst](<reverse_proxy.rst>) for instructions on how to correctly
configure a reverse proxy.

## Running a Demo Federation of Synapses

If you want to get up and running quickly with a trio of homeservers in a
private federation, there is a script in the ``demo`` directory. This is mainly
useful just for development purposes. See [demo/README](<../demo/README>).
