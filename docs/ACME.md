# ACME

From version 1.0 (June 2019) onwards, Synapse requires valid TLS
certificates for communication between servers (by default on port
`8448`) in addition to those that are client-facing (port `443`). To
help homeserver admins fulfil this new requirement, Synapse v0.99.0
introduced support for automatically provisioning certificates through 
[Let's Encrypt](https://letsencrypt.org/) using the ACME protocol.

## Deprecation of ACME v1

In [March 2019](https://community.letsencrypt.org/t/end-of-life-plan-for-acmev1/88430),
Let's Encrypt announced that they were deprecating version 1 of the ACME
protocol, with the plan to disable the use of it for new accounts in
November 2019, and for existing accounts in June 2020.

Synapse doesn't currently support version 2 of the ACME protocol, which
means that:

* for existing installs, Synapse's built-in ACME support will continue
  to work until June 2020.
* for new installs, this feature will not work at all.

Either way, it is recommended to move from Synapse's ACME support
feature to an external automated tool such as [certbot](https://github.com/certbot/certbot)
(or browse [this list](https://letsencrypt.org/fr/docs/client-options/)
for an alternative ACME client).

It's also recommended to use a reverse proxy for the server-facing
communications (more documentation about this can be found
[here](/docs/reverse_proxy.md)) as well as the client-facing ones and
have it serve the certificates.

In case you can't do that and need Synapse to serve them itself, make
sure to set the `tls_certificate_path` configuration setting to the path
of the certificate (make sure to use the certificate containing the full
certification chain, e.g. `fullchain.pem` if using certbot) and
`tls_private_key_path` to the path of the matching private key. Note
that in this case you will need to restart Synapse after each
certificate renewal so that Synapse stops using the old certificate.

If you still want to use Synapse's built-in ACME support, the rest of
this document explains how to set it up. 

## Initial setup 

In the case that your `server_name` config variable is the same as
the hostname that the client connects to, then the same certificate can be
used between client and federation ports without issue.

If your configuration file does not already have an `acme` section, you can
generate an example config by running the `generate_config` executable. For
example:

```
~/synapse/env3/bin/generate_config
```

You will need to provide Let's Encrypt (or another ACME provider) access to
your Synapse ACME challenge responder on port 80, at the domain of your
homeserver. This requires you to either change the port of the ACME listener
provided by Synapse to a high port and reverse proxy to it, or use a tool
like `authbind` to allow Synapse to listen on port 80 without root access.
(Do not run Synapse with root permissions!) Detailed instructions are
available under "ACME setup" below.

If you already have certificates, you will need to back up or delete them
(files `example.com.tls.crt` and `example.com.tls.key` in Synapse's root
directory), Synapse's ACME implementation will not overwrite them.

## ACME setup

The main steps for enabling ACME support in short summary are:

1. Allow Synapse to listen for incoming ACME challenges.
1. Enable ACME support in `homeserver.yaml`.
1. Move your old certificates (files `example.com.tls.crt` and `example.com.tls.key` out of the way if they currently exist at the paths specified in `homeserver.yaml`.
1. Restart Synapse.

Detailed instructions for each step are provided below.

### Listening on port 80

In order for Synapse to complete the ACME challenge to provision a
certificate, it needs access to port 80. Typically listening on port 80 is
only granted to applications running as root. There are thus two solutions to
this problem.

#### Using a reverse proxy

A reverse proxy such as Apache or nginx allows a single process (the web
server) to listen on port 80 and proxy traffic to the appropriate program
running on your server. It is the recommended method for setting up ACME as
it allows you to use your existing webserver while also allowing Synapse to
provision certificates as needed.

For nginx users, add the following line to your existing `server` block:

```
location /.well-known/acme-challenge {
    proxy_pass http://localhost:8009;
}
```

For Apache, add the following to your existing webserver config:

```
ProxyPass /.well-known/acme-challenge http://localhost:8009/.well-known/acme-challenge
```

Make sure to restart/reload your webserver after making changes.

Now make the relevant changes in `homeserver.yaml` to enable ACME support:

```
acme:
    enabled: true
    port: 8009
```

#### Authbind

`authbind` allows a program which does not run as root to bind to
low-numbered ports in a controlled way. The setup is simpler, but requires a
webserver not to already be running on port 80. **This includes every time
Synapse renews a certificate**, which may be cumbersome if you usually run a
web server on port 80. Nevertheless, if you're sure port 80 is not being used
for any other purpose then all that is necessary is the following:

Install `authbind`. For example, on Debian/Ubuntu:

```
sudo apt-get install authbind
```

Allow `authbind` to bind port 80:

```
sudo touch /etc/authbind/byport/80
sudo chmod 777 /etc/authbind/byport/80
```

When Synapse is started, use the following syntax:

```
authbind --deep <synapse start command>
```

Make the relevant changes in `homeserver.yaml` to enable ACME support:

```
acme:
    enabled: true
```

### (Re)starting synapse

Ensure that the certificate paths specified in `homeserver.yaml` (`tls_certificate_path` and `tls_private_key_path`) do not currently point to any files. Synapse will not provision certificates if files exist, as it does not want to overwrite existing certificates.

Finally, start/restart Synapse.
