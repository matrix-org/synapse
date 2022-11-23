# eturnal TURN server

The following sections describe how to install [eturnal](<https://github.com/processone/eturnal>) 
(which implements the TURN REST API).

## `eturnal` setup

### Initial installation

The `eturnal` TURN server implementation is available from a variety of sources 
such as native package managers, binary packages, installation from source or 
[container image](https://eturnal.net/documentation/code/docker.html). They are 
all described [here](https://github.com/processone/eturnal#installation).

Quick-Test instructions in a [Linux Shell](https://github.com/processone/eturnal/blob/master/QUICK-TEST.md) 
or with [Docker](https://github.com/processone/eturnal/blob/master/docker-k8s/QUICK-TEST.md) 
are available as well.

### Configuration

After installation, `eturnal` usually ships a [default configuration file](https://github.com/processone/eturnal/blob/master/config/eturnal.yml) 
here: `/etc/eturnal.yml` (and, if not found there, there is a backup file here: 
`/opt/eturnal/etc/eturnal.yml`). It uses the (indentation-sensitive!) [YAML](https://en.wikipedia.org/wiki/YAML) 
format. The file contains further explanations.

Here are some hints how to configure eturnal on your [host machine](https://github.com/processone/eturnal#configuration) 
or when using e.g. [Docker](https://eturnal.net/documentation/code/docker.html).
You may also further deep dive into the [reference documentation](https://eturnal.net/documentation/).

`eturnal` runs out of the box with the default configuration. To enable TURN and 
to integrate it with your homeserver, some aspects in `eturnal`'s default configuration file 
must be edited:

1.  Homeserver's [`turn_shared_secret`](../../usage/configuration/config_documentation.md#turn_shared_secret) 
    and eturnal's shared `secret` for authentication

    Both need to have the same value. Uncomment and adjust this line in `eturnal`'s 
    configuration file:

    ```yaml
    secret: "long-and-cryptic"     # Shared secret, CHANGE THIS.
    ```

    One way to generate a `secret` is with `pwgen`:

    ```sh
    pwgen -s 64 1
    ```

1.  Public IP address

    If your TURN server is behind NAT, the NAT gateway must have an external,
    publicly-reachable IP address. `eturnal` tries to autodetect the public IP address, 
    however, it may also be configured by uncommenting and adjusting this line, so 
    `eturnal` advertises that address to connecting clients:

    ```yaml
    relay_ipv4_addr: "203.0.113.4" # The server's public IPv4 address.
    ```

    If your NAT gateway is reachable over both IPv4 and IPv6, you may
    configure `eturnal` to advertise each available address:

    ```yaml
    relay_ipv4_addr: "203.0.113.4" # The server's public IPv4 address.
    relay_ipv6_addr: "2001:db8::4" # The server's public IPv6 address (optional).
    ```

    When advertising an external IPv6 address, ensure that the firewall and
    network settings of the system running your TURN server are configured to
    accept IPv6 traffic, and that the TURN server is listening on the local
    IPv6 address that is mapped by NAT to the external IPv6 address.

1.  Logging

    If `eturnal` was started by systemd, log files are written into the
    `/var/log/eturnal` directory by default. In order to log to the [journal](https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html)
    instead, the `log_dir` option can be set to `stdout` in the configuration file.

1.  Security considerations

    Consider your security settings. TURN lets users request a relay which will
    connect to arbitrary IP addresses and ports. The following configuration is
    suggested as a minimum starting point, [see also the official documentation](https://eturnal.net/documentation/#blacklist):

    ```yaml
    ## Reject TURN relaying from/to the following addresses/networks:
    blacklist:                 # This is the default blacklist.
        - "127.0.0.0/8"        # IPv4 loopback.
        - "::1"                # IPv6 loopback.
        - recommended          # Expands to a number of networks recommended to be
                               # blocked, but includes private networks. Those
                               # would have to be 'whitelist'ed if eturnal serves
                               # local clients/peers within such networks.
    ```

    To whitelist IP addresses or specific (private) networks, you need to **add** a 
    whitelist part into the configuration file, e.g.:

    ```yaml
    whitelist:
        - "192.168.0.0/16"
        - "203.0.113.113"
        - "2001:db8::/64"
    ```

    The more specific, the better.

1.  TURNS (TURN via TLS/DTLS)

    Also consider supporting TLS/DTLS. To do this, adjust the following settings
    in the `eturnal.yml` configuration file (TLS parts should not be commented anymore):

    ```yaml
    listen:
        - ip: "::"
          port: 3478
          transport: udp
        - ip: "::"
          port: 3478
          transport: tcp
        - ip: "::"
          port: 5349
          transport: tls

    ## TLS certificate/key files (must be readable by 'eturnal' user!):
    tls_crt_file: /etc/eturnal/tls/crt.pem
    tls_key_file: /etc/eturnal/tls/key.pem
    ```

    In this case, replace the `turn:` schemes in homeserver's `turn_uris` settings
    with `turns:`. More is described [here](../../usage/configuration/config_documentation.md#turn_uris).

    We recommend that you only try to set up TLS/DTLS once you have set up a
    basic installation and got it working.

    NB: If your TLS certificate was provided by Let's Encrypt, TLS/DTLS will
    not work with any Matrix client that uses Chromium's WebRTC library. This
    currently includes Element Android & iOS; for more details, see their
    [respective](https://github.com/vector-im/element-android/issues/1533)
    [issues](https://github.com/vector-im/element-ios/issues/2712) as well as the underlying
    [WebRTC issue](https://bugs.chromium.org/p/webrtc/issues/detail?id=11710).
    Consider using a ZeroSSL certificate for your TURN server as a working alternative.

1.  Firewall

    Ensure your firewall allows traffic into the TURN server on the ports
    you've configured it to listen on (By default: 3478 and 5349 for TURN
    traffic (remember to allow both TCP and UDP traffic), and ports 49152-65535
    for the UDP relay.)

1.  Reload/ restarting `eturnal`

    Changes in the configuration file require `eturnal` to reload/ restart, this
    can be achieved by:

    ```sh
    eturnalctl reload
    ```
    
    `eturnal` performs a configuration check before actually reloading/ restarting
    and provides hints, if something is not correctly configured.

### eturnalctl opterations script

`eturnal` offers a handy [operations script](https://eturnal.net/documentation/#Operation) 
which can be called e.g. to check, whether the service is up, to restart the service, 
to query how many active sessions exist, to change logging behaviour and so on.

Hint: If `eturnalctl` is not part of your `$PATH`, consider either sym-linking it (e.g. ´ln -s /opt/eturnal/bin/eturnalctl /usr/local/bin/eturnalctl´) or call it from the default `eturnal` directory directly: e.g. `/opt/eturnal/bin/eturnalctl info`
