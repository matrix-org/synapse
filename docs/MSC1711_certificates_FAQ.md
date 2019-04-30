# MSC1711 Certificates FAQ

The goal of Synapse 0.99.0 is to act as a stepping stone to Synapse 1.0.0. It
supports the r0.1 release of the server to server specification, but is
compatible with both the legacy Matrix federation behaviour (pre-r0.1) as well
as post-r0.1 behaviour, in order to allow for a smooth upgrade across the
federation.

The most important thing to know is that Synapse 1.0.0 will require a valid TLS
certificate on federation endpoints. Self signed certificates will not be
sufficient.

Synapse 0.99.0 makes it easy to configure TLS certificates and will
interoperate with both >= 1.0.0 servers as well as existing servers yet to
upgrade.

**It is critical that all admins upgrade to 0.99.0 and configure a valid TLS
certificate.** Admins will have 1 month to do so, after which 1.0.0 will be
released and those servers without a valid certificate will not longer be able
to federate with >= 1.0.0 servers.

Full details on how to carry out this configuration change is given
[below](#configuring-certificates-for-compatibility-with-synapse-100). A
timeline and some frequently asked questions are also given below.

For more details and context on the release of the r0.1 Server/Server API and
imminent Matrix 1.0 release, you can also see our
[main talk from FOSDEM 2019](https://matrix.org/blog/2019/02/04/matrix-at-fosdem-2019/).

## Contents
* Timeline
* Configuring certificates for compatibility with Synapse 1.0
* FAQ
  * Synapse 0.99.0 has just been released, what do I need to do right now?
  * How do I upgrade?
  * What will happen if I do not set up a valid federation certificate
    immediately?
  * What will happen if I do nothing at all?
  * When do I need a SRV record or .well-known URI?
  * Can I still use an SRV record?
  * I have created a .well-known URI. Do I still need an SRV record?
  * It used to work just fine, why are you breaking everything?
  * Can I manage my own certificates rather than having Synapse renew
    certificates itself?
  * Do you still recommend against using a reverse proxy on the federation port?
  * Do I still need to give my TLS certificates to Synapse if I am using a
    reverse proxy?
  * Do I need the same certificate for the client and federation port?
  * How do I tell Synapse to reload my keys/certificates after I replace them?

## Timeline

**5th Feb 2019  - Synapse 0.99.0 is released.**

All server admins are encouraged to upgrade.

0.99.0:

-   provides support for ACME to make setting up Let's Encrypt certs easy, as
    well as .well-known support.

-   does not enforce that a valid CA cert is present on the federation API, but
    rather makes it easy to set one up.

-   provides support for .well-known

Admins should upgrade and configure a valid CA cert. Homeservers that require a
.well-known entry (see below), should retain their SRV record and use it
alongside their .well-known record.

**>= 5th March 2019  - Synapse 1.0.0 is released**

1.0.0 will land no sooner than 1 month after 0.99.0, leaving server admins one
month after 5th February to upgrade to 0.99.0 and deploy their certificates. In
accordance with the the [S2S spec](https://matrix.org/docs/spec/server_server/r0.1.0.html)
1.0.0 will enforce certificate validity. This means that any homeserver without a
valid certificate after this point will no longer be able to federate with
1.0.0 servers.


## Configuring certificates for compatibility with Synapse 1.0.0

### If you do not currently have an SRV record

In this case, your `server_name` points to the host where your Synapse is
running. There is no need to create a `.well-known` URI or an SRV record, but
you will need to give Synapse a valid, signed, certificate.

The easiest way to do that is with Synapse's built-in ACME (Let's Encrypt)
support. Full details are in [ACME.md](./ACME.md) but, in a nutshell:

 1. Allow Synapse to listen on port 80 with `authbind`, or forward it from a
    reverse proxy.
 2. Enable acme support in `homeserver.yaml`.
 3. Move your old certificates out of the way.
 4. Restart Synapse.

### If you do have an SRV record currently

If you are using an SRV record, your matrix domain (`server_name`) may not
point to the same host that your Synapse is running on (the 'target
domain'). (If it does, you can follow the recommendation above; otherwise, read
on.)

Let's assume that your `server_name` is `example.com`, and your Synapse is
hosted at a target domain of `customer.example.net`. Currently you should have
an SRV record which looks like:

```
_matrix._tcp.example.com. IN SRV 10 5 8000 customer.example.net.
```

In this situation, you have three choices for how to proceed:

#### Option 1: give Synapse a certificate for your matrix domain

Synapse 1.0 will expect your server to present a TLS certificate for your
`server_name` (`example.com` in the above example). You can achieve this by
doing one of the following:

 * Acquire a certificate for the `server_name` yourself (for example, using
   `certbot`), and give it and the key to Synapse via `tls_certificate_path`
   and `tls_private_key_path`, or:

 * Use Synapse's [ACME support](./ACME.md), and forward port 80 on the
   `server_name` domain to your Synapse instance.

#### Option 2: run Synapse behind a reverse proxy

If you have an existing reverse proxy set up with correct TLS certificates for
your domain, you can simply route all traffic through the reverse proxy by
updating the SRV record appropriately (or removing it, if the proxy listens on
8448).

See [reverse_proxy.rst](reverse_proxy.rst) for information on setting up a
reverse proxy.

#### Option 3: add a .well-known file to delegate your matrix traffic

This will allow you to keep Synapse on a separate domain, without having to
give it a certificate for the matrix domain.

You can do this with a `.well-known` file as follows:

 1. Keep the SRV record in place - it is needed for backwards compatibility
    with Synapse 0.34 and earlier.

 2. Give synapse a certificate corresponding to the target domain
    (`customer.example.net` in the above example). Currently Synapse's ACME
    support [does not support
    this](https://github.com/matrix-org/synapse/issues/4552), so you will have
    to acquire a certificate yourself and give it to Synapse via
    `tls_certificate_path` and `tls_private_key_path`.

 3. Restart Synapse to ensure the new certificate is loaded.

 4. Arrange for a `.well-known` file at
    `https://<server_name>/.well-known/matrix/server` with contents:

    ```json
    {"m.server": "<target server name>"}
    ```

    where the target server name is resolved as usual (i.e. SRV lookup, falling
    back to talking to port 8448).

    In the above example, where synapse is listening on port 8000,
    `https://example.com/.well-known/matrix/server` should have `m.server` set to one of:

    1. `customer.example.net` ─ with a SRV record on
       `_matrix._tcp.customer.example.com` pointing to port 8000, or:

    2. `customer.example.net` ─ updating synapse to listen on the default port
       8448, or:

    3. `customer.example.net:8000` ─ ensuring that if there is a reverse proxy
       on `customer.example.net:8000` it correctly handles HTTP requests with
       Host header set to `customer.example.net:8000`.

## FAQ

### Synapse 0.99.0 has just been released, what do I need to do right now?

Upgrade as soon as you can in preparation for Synapse 1.0.0, and update your
TLS certificates as [above](#configuring-certificates-for-compatibility-with-synapse-100).

### What will happen if I do not set up a valid federation certificate immediately?

Nothing initially, but once 1.0.0 is in the wild it will not be possible to
federate with 1.0.0 servers.

### What will happen if I do nothing at all?

If the admin takes no action at all, and remains on a Synapse < 0.99.0 then the
homeserver will be unable to federate with those who have implemented
.well-known. Then, as above, once the month upgrade window has expired the
homeserver will not be able to federate with any Synapse >= 1.0.0

### When do I need a SRV record or .well-known URI?

If your homeserver listens on the default federation port (8448), and your
`server_name` points to the host that your homeserver runs on, you do not need an
SRV record or `.well-known/matrix/server` URI.

For instance, if you registered `example.com` and pointed its DNS A record at a
fresh Upcloud VPS or similar, you could install Synapse 0.99 on that host,
giving it a server_name of `example.com`, and it would automatically generate a
valid TLS certificate for you via Let's Encrypt and no SRV record or
`.well-known` URI would be needed.

This is the common case, although you can add an SRV record or
`.well-known/matrix/server` URI for completeness if you wish.

**However**, if your server does not listen on port 8448, or if your `server_name`
does not point to the host that your homeserver runs on, you will need to let
other servers know how to find it.

In this case, you should see ["If you do have an SRV record
currently"](#if-you-do-have-an-srv-record-currently) above.

### Can I still use an SRV record?

Firstly, if you didn't need an SRV record before (because your server is
listening on port 8448 of your server_name), you certainly don't need one now:
the defaults are still the same.

If you previously had an SRV record, you can keep using it provided you are
able to give Synapse a TLS certificate corresponding to your server name. For
example, suppose you had the following SRV record, which directs matrix traffic
for example.com to matrix.example.com:443:

```
_matrix._tcp.example.com. IN SRV 10 5 443 matrix.example.com
```

In this case, Synapse must be given a certificate for example.com - or be
configured to acquire one from Let's Encrypt.

If you are unable to give Synapse a certificate for your server_name, you will
also need to use a .well-known URI instead. However, see also "I have created a
.well-known URI. Do I still need an SRV record?".

### I have created a .well-known URI. Do I still need an SRV record?

As of Synapse 0.99, Synapse will first check for the existence of a `.well-known`
URI and follow any delegation it suggests. It will only then check for the
existence of an SRV record.

That means that the SRV record will often be redundant. However, you should
remember that there may still be older versions of Synapse in the federation
which do not understand `.well-known` URIs, so if you removed your SRV record you
would no longer be able to federate with them.

It is therefore best to leave the SRV record in place for now. Synapse 0.34 and
earlier will follow the SRV record (and not care about the invalid
certificate). Synapse 0.99 and later will follow the .well-known URI, with the
correct certificate chain.

### It used to work just fine, why are you breaking everything?

We have always wanted Matrix servers to be as easy to set up as possible, and
so back when we started federation in 2014 we didn't want admins to have to go
through the cumbersome process of buying a valid TLS certificate to run a
server. This was before Let's Encrypt came along and made getting a free and
valid TLS certificate straightforward. So instead, we adopted a system based on
[Perspectives](https://en.wikipedia.org/wiki/Convergence_(SSL)): an approach
where you check a set of "notary servers" (in practice, homeservers) to vouch
for the validity of a certificate rather than having it signed by a CA. As long
as enough different notaries agree on the certificate's validity, then it is
trusted.

However, in practice this has never worked properly. Most people only use the
default notary server (matrix.org), leading to inadvertent centralisation which
we want to eliminate. Meanwhile, we never implemented the full consensus
algorithm to query the servers participating in a room to determine consensus
on whether a given certificate is valid. This is fiddly to get right
(especially in face of sybil attacks), and we found ourselves questioning
whether it was worth the effort to finish the work and commit to maintaining a
secure certificate validation system as opposed to focusing on core Matrix
development.

Meanwhile, Let's Encrypt came along in 2016, and put the final nail in the
coffin of the Perspectives project (which was already pretty dead). So, the
Spec Core Team decided that a better approach would be to mandate valid TLS
certificates for federation alongside the rest of the Web. More details can be
found in
[MSC1711](https://github.com/matrix-org/matrix-doc/blob/master/proposals/1711-x509-for-federation.md#background-the-failure-of-the-perspectives-approach).

This results in a breaking change, which is disruptive, but absolutely critical
for the security model. However, the existence of Let's Encrypt as a trivial
way to replace the old self-signed certificates with valid CA-signed ones helps
smooth things over massively, especially as Synapse can now automate Let's
Encrypt certificate generation if needed.

### Can I manage my own certificates rather than having Synapse renew certificates itself?

Yes, you are welcome to manage your certificates yourself. Synapse will only
attempt to obtain certificates from Let's Encrypt if you configure it to do
so.The only requirement is that there is a valid TLS cert present for
federation end points.

### Do you still recommend against using a reverse proxy on the federation port?

We no longer actively recommend against using a reverse proxy. Many admins will
find it easier to direct federation traffic to a reverse proxy and manage their
own TLS certificates, and this is a supported configuration.

See [reverse_proxy.rst](reverse_proxy.rst) for information on setting up a
reverse proxy.

### Do I still need to give my TLS certificates to Synapse if I am using a reverse proxy?

Practically speaking, this is no longer necessary.

If you are using a reverse proxy for all of your TLS traffic, then you can set
`no_tls: True`. In that case, the only reason Synapse needs the certificate is
to populate a legacy 'tls_fingerprints' field in the federation API. This is
ignored by Synapse 0.99.0 and later, and the only time pre-0.99 Synapses will
check it is when attempting to fetch the server keys - and generally this is
delegated via `matrix.org`, which is on 0.99.0.

However, there is a bug in Synapse 0.99.0
[4554](<https://github.com/matrix-org/synapse/issues/4554>) which prevents
Synapse from starting if you do not give it a TLS certificate. To work around
this, you can give it any TLS certificate at all. This will be fixed soon.

### Do I need the same certificate for the client and federation port?

No. There is nothing stopping you from using different certificates,
particularly if you are using a reverse proxy. However, Synapse will use the
same certificate on any ports where TLS is configured.

### How do I tell Synapse to reload my keys/certificates after I replace them?

Synapse will reload the keys and certificates when it receives a SIGHUP - for
example `kill -HUP $(cat homeserver.pid)`. Alternatively, simply restart
Synapse, though this will result in downtime while it restarts.
