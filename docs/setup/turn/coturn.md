# coturn TURN server

The following sections describe how to install [coturn](<https://github.com/coturn/coturn>) (which implements the TURN REST API).

## `coturn` setup

### Initial installation

The TURN daemon `coturn` is available from a variety of sources such as native package managers, or installation from source.

#### Debian and Ubuntu based distributions

Just install the debian package:

```sh
sudo apt install coturn
```

This will install and start a systemd service called `coturn`.

#### Source installation

1. Download the [latest release](https://github.com/coturn/coturn/releases/latest) from github.  Unpack it and `cd` into the directory.

1.  Configure it:

    ```sh
    ./configure
    ```

    You may need to install `libevent2`: if so, you should do so in
    the way recommended by your operating system. You can ignore
    warnings about lack of database support: a database is unnecessary
    for this purpose.

1.  Build and install it:

    ```sh
    make
    sudo make install
    ```

### Configuration

1.  Create or edit the config file in `/etc/turnserver.conf`. The relevant
    lines, with example values, are:

    ```
    use-auth-secret
    static-auth-secret=[your secret key here]
    realm=turn.myserver.org
    ```

    See `turnserver.conf` for explanations of the options. One way to generate
    the `static-auth-secret` is with `pwgen`:

    ```sh
    pwgen -s 64 1
    ```

    A `realm` must be specified, but its value is somewhat arbitrary. (It is
    sent to clients as part of the authentication flow.) It is conventional to
    set it to be your server name.

1.  You will most likely want to configure `coturn` to write logs somewhere. The
    easiest way is normally to send them to the syslog:

    ```sh
    syslog
    ```

    (in which case, the logs will be available via `journalctl -u coturn` on a
    systemd system). Alternatively, `coturn` can be configured to write to a
    logfile - check the example config file supplied with `coturn`.

1.  Consider your security settings. TURN lets users request a relay which will
    connect to arbitrary IP addresses and ports. The following configuration is
    suggested as a minimum starting point:

    ```
    # VoIP traffic is all UDP. There is no reason to let users connect to arbitrary TCP endpoints via the relay.
    no-tcp-relay

    # don't let the relay ever try to connect to private IP address ranges within your network (if any)
    # given the turn server is likely behind your firewall, remember to include any privileged public IPs too.
    denied-peer-ip=10.0.0.0-10.255.255.255
    denied-peer-ip=192.168.0.0-192.168.255.255
    denied-peer-ip=172.16.0.0-172.31.255.255

    # recommended additional local peers to block, to mitigate external access to internal services.
    # https://www.rtcsec.com/article/slack-webrtc-turn-compromise-and-bug-bounty/#how-to-fix-an-open-turn-relay-to-address-this-vulnerability
    no-multicast-peers
    denied-peer-ip=0.0.0.0-0.255.255.255
    denied-peer-ip=100.64.0.0-100.127.255.255
    denied-peer-ip=127.0.0.0-127.255.255.255
    denied-peer-ip=169.254.0.0-169.254.255.255
    denied-peer-ip=192.0.0.0-192.0.0.255
    denied-peer-ip=192.0.2.0-192.0.2.255
    denied-peer-ip=192.88.99.0-192.88.99.255
    denied-peer-ip=198.18.0.0-198.19.255.255
    denied-peer-ip=198.51.100.0-198.51.100.255
    denied-peer-ip=203.0.113.0-203.0.113.255
    denied-peer-ip=240.0.0.0-255.255.255.255

    # special case the turn server itself so that client->TURN->TURN->client flows work
    # this should be one of the turn server's listening IPs
    allowed-peer-ip=10.0.0.1

    # consider whether you want to limit the quota of relayed streams per user (or total) to avoid risk of DoS.
    user-quota=12 # 4 streams per video call, so 12 streams = 3 simultaneous relayed calls per user.
    total-quota=1200
    ```

1.  Also consider supporting TLS/DTLS. To do this, add the following settings
    to `turnserver.conf`:

    ```
    # TLS certificates, including intermediate certs.
    # For Let's Encrypt certificates, use `fullchain.pem` here.
    cert=/path/to/fullchain.pem

    # TLS private key file
    pkey=/path/to/privkey.pem

    # Ensure the configuration lines that disable TLS/DTLS are commented-out or removed
    #no-tls
    #no-dtls
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

1.  If your TURN server is behind NAT, the NAT gateway must have an external,
    publicly-reachable IP address. You must configure `coturn` to advertise that
    address to connecting clients:

    ```
    external-ip=EXTERNAL_NAT_IPv4_ADDRESS
    ```

    You may optionally limit the TURN server to listen only on the local
    address that is mapped by NAT to the external address:

    ```
    listening-ip=INTERNAL_TURNSERVER_IPv4_ADDRESS
    ```

    If your NAT gateway is reachable over both IPv4 and IPv6, you may
    configure `coturn` to advertise each available address:

    ```
    external-ip=EXTERNAL_NAT_IPv4_ADDRESS
    external-ip=EXTERNAL_NAT_IPv6_ADDRESS
    ```

    When advertising an external IPv6 address, ensure that the firewall and
    network settings of the system running your TURN server are configured to
    accept IPv6 traffic, and that the TURN server is listening on the local
    IPv6 address that is mapped by NAT to the external IPv6 address.

1.  (Re)start the turn server:

    * If you used the Debian package (or have set up a systemd unit yourself):
      ```sh
      sudo systemctl restart coturn
      ```

    * If you built from source:

      ```sh
      /usr/local/bin/turnserver -o
      ```
