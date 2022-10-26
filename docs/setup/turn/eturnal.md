# eturnal TURN server

The following sections describe how to install [eturnal](<https://github.com/processone/eturnal>) (which implements the TURN REST API).

## `eturnal` setup

### Initial installation

The `eturnal` TURN server implementation is available from a variety of sources such as native package managers, binary packages, installation from source or [container image](https://eturnal.net/documentation/code/docker.html).

On **APT-based** Linux distributions, run:

```sh
sudo apt install extrepo
sudo extrepo enable eturnal
sudo apt update
sudo apt install eturnal
```

On **DNF-based** Linux distributions, run:

```sh
sudo dnf config-manager --add-repo https://eturnal.net/eturnal.repo
sudo dnf install eturnal
sudo systemctl --now enable eturnal
```

On **YUM-based** Linux distributions, run:

```sh
sudo yum-config-manager --add-repo https://eturnal.net/eturnal.repo
sudo yum install eturnal
sudo systemctl --now enable eturnal
```

On SUSE Linux Enterprise and openSUSE systems, [distribution repositories](https://software.opensuse.org/download/?package=eturnal&project=devel:languages:erlang)
can be used instead. On other Linux systems, the binary release can be installed
as [described](https://eturnal.net/documentation/#Installation) in the reference documentation. For Windows, an installer is
[available](https://eturnal.net/windows/). On other platforms, `eturnal` is [built from source](https://github.com/processone/eturnal/blob/master/INSTALL.md).

### Configuration

1.  Create or edit the config file in `/etc/eturnal.yml`. 
    See the [example configuration](https://github.com/processone/eturnal/blob/master/config/eturnal.yml) for explanations of the options.
    
    The relevant lines, with example values, are:

    ```yaml
    eturnal:
        secret: "long-and-cryptic"     # Shared secret, CHANGE THIS.
    ```

    One way to generate the `secret` is with `pwgen`:

    ```sh
    pwgen -s 64 1
    ```

1.  If your TURN server is behind NAT, the NAT gateway must have an external,
    publicly-reachable IP address. `eturnal` tries to autodetect the public IP address, however, it may also be configured, so `eturnal` advertises that
    address to connecting clients:

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

1.  If eturnal was started by systemd, log files are written into the
    `/var/log/eturnal` directory by default. In order to log to the [journal](https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html)
    instead, the `log_dir` option can be set to `stdout` in the configuration file.

1.  Consider your security settings. TURN lets users request a relay which will
    connect to arbitrary IP addresses and ports. The following configuration is
    suggested as a minimum starting point, [see also the official documentation](https://eturnal.net/documentation/#blacklist):

    ```yaml
        ## Reject TURN relaying from/to the following addresses/networks:
        blacklist:                # This is the default blacklist.
            - "127.0.0.0/8"         # IPv4 loopback.
            - "::1"                 # IPv6 loopback.
            #- recommended          # Expands to a number of networks recommended to be
                                    # blocked, but includes private networks. Those
                                    # would have to be 'whitelist'ed if eturnal serves
                                    # local clients/peers within such networks.
    ```

    To block further recommend address ranges, uncomment the `- recommended` part in the configuration file.

1.  Also consider supporting TLS/DTLS. To do this, adjust the following settings
    in the `eturnal.yml` configuration file (TLS parts should not be commented anymore):

    ```yaml
        listen:
            -
            ip: "::"
            port: 3478
            transport: udp
            -
            ip: "::"
            port: 3478
            transport: tcp
            #-
            #  ip: "::"
            #  port: 5349
            #  transport: tls

        ## TLS certificate/key files (must be readable by 'eturnal' user!):
        #tls_crt_file: /etc/eturnal/tls/crt.pem
        #tls_key_file: /etc/eturnal/tls/key.pem
    ```

    In this case, replace the `turn:` schemes in the `turn_uris` settings below
    with `turns:`.

    We recommend that you only try to set up TLS/DTLS once you have set up a
    basic installation and got it working.

    NB: If your TLS certificate was provided by Let's Encrypt, TLS/DTLS will
    not work with any Matrix client that uses Chromium's WebRTC library. This
    currently includes Element Android & iOS; for more details, see their
    [respective](https://github.com/vector-im/element-android/issues/1533)
    [issues](https://github.com/vector-im/element-ios/issues/2712) as well as the underlying
    [WebRTC issue](https://bugs.chromium.org/p/webrtc/issues/detail?id=11710).
    Consider using a ZeroSSL certificate for your TURN server as a working alternative.

1.  Ensure your firewall allows traffic into the TURN server on the ports
    you've configured it to listen on (By default: 3478 and 5349 for TURN
    traffic (remember to allow both TCP and UDP traffic), and ports 49152-65535
    for the UDP relay.)

1.  (Re)start the turn server:

    ```sh
    eturnalctl reload
    ```

### eturnalctl opterations script

`eturnal` offers a handy [operations script](https://eturnal.net/documentation/#Operation) which can be called e.g. to check, whether the service is up, to restart the service, to querrz how many active sessions exist, to change logging behaviour and so on.