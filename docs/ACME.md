# ACME

Synapse v1.0 will require valid TLS certificates for communication between
servers (port `8448` by default) in addition to those that are client-facing
(port `443`). If you do not already have a valid certificate for your domain,
the easiest way to get one is with Synapse's new ACME support, which will use
the ACME protocol to provision a certificate automatically. Synapse v0.99.0+
will provision server-to-server certificates automatically for you for free
through [Let's Encrypt](https://letsencrypt.org/) if you tell it to.

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

You may wish to use alternate methods such as Certbot to obtain a certificate
from Let's Encrypt, depending on your server configuration. Of course, if you
already have a valid certificate for your homeserver's domain, that can be
placed in Synapse's config directory without the need for any ACME setup.

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
