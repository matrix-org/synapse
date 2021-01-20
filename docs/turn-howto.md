# Overview

This document explains how to enable VoIP relaying on your Home Server with
TURN.

The synapse Matrix Home Server supports integration with TURN server via the
[TURN server REST API](<http://tools.ietf.org/html/draft-uberti-behave-turn-rest-00>). This
allows the Home Server to generate credentials that are valid for use on the
TURN server through the use of a secret shared between the Home Server and the
TURN server.

The following sections describe how to install [coturn](<https://github.com/coturn/coturn>) (which implements the TURN REST API) and integrate it with synapse.

## Requirements

For TURN relaying with `coturn` to work, it must be hosted on a server/endpoint with a public IP.

Hosting TURN behind a NAT (even with appropriate port forwarding) is known to cause issues
and to often not work.

## `coturn` setup

### Initial installation

The TURN daemon `coturn` is available from a variety of sources such as native package managers, or installation from source.

#### Debian installation

Just install the debian package:

```sh
apt install coturn
```

This will install and start a systemd service called `coturn`.

#### Source installation

1. Download the [latest release](https://github.com/coturn/coturn/releases/latest) from github.  Unpack it and `cd` into the directory.

1.  Configure it:

        ./configure

    You may need to install `libevent2`: if so, you should do so in
    the way recommended by your operating system. You can ignore
    warnings about lack of database support: a database is unnecessary
    for this purpose.

1.  Build and install it:

        make
        make install

### Configuration

1.  Create or edit the config file in `/etc/turnserver.conf`. The relevant
    lines, with example values, are:

        use-auth-secret
        static-auth-secret=[your secret key here]
        realm=turn.myserver.org

    See `turnserver.conf` for explanations of the options. One way to generate
    the `static-auth-secret` is with `pwgen`:

        pwgen -s 64 1

    A `realm` must be specified, but its value is somewhat arbitrary. (It is
    sent to clients as part of the authentication flow.) It is conventional to
    set it to be your server name.

1.  You will most likely want to configure coturn to write logs somewhere. The
    easiest way is normally to send them to the syslog:

        syslog

    (in which case, the logs will be available via `journalctl -u coturn` on a
    systemd system). Alternatively, coturn can be configured to write to a
    logfile - check the example config file supplied with coturn.

1.  Consider your security settings. TURN lets users request a relay which will
    connect to arbitrary IP addresses and ports. The following configuration is
    suggested as a minimum starting point:

        # VoIP traffic is all UDP. There is no reason to let users connect to arbitrary TCP endpoints via the relay.
        no-tcp-relay

        # don't let the relay ever try to connect to private IP address ranges within your network (if any)
        # given the turn server is likely behind your firewall, remember to include any privileged public IPs too.
        denied-peer-ip=10.0.0.0-10.255.255.255
        denied-peer-ip=192.168.0.0-192.168.255.255
        denied-peer-ip=172.16.0.0-172.31.255.255

        # special case the turn server itself so that client->TURN->TURN->client flows work
        allowed-peer-ip=10.0.0.1

        # consider whether you want to limit the quota of relayed streams per user (or total) to avoid risk of DoS.
        user-quota=12 # 4 streams per video call, so 12 streams = 3 simultaneous relayed calls per user.
        total-quota=1200

1.  Also consider supporting TLS/DTLS. To do this, add the following settings
    to `turnserver.conf`:

        # TLS certificates, including intermediate certs.
        # For Let's Encrypt certificates, use `fullchain.pem` here.
        cert=/path/to/fullchain.pem

        # TLS private key file
        pkey=/path/to/privkey.pem

    In this case, replace the `turn:` schemes in the `turn_uri` settings below
    with `turns:`.

    We recommend that you only try to set up TLS/DTLS once you have set up a
    basic installation and got it working.

1.  Ensure your firewall allows traffic into the TURN server on the ports
    you've configured it to listen on (By default: 3478 and 5349 for TURN
    traffic (remember to allow both TCP and UDP traffic), and ports 49152-65535
    for the UDP relay.)

1.  We do not recommend running a TURN server behind NAT, and are not aware of
    anyone doing so successfully.

    If you want to try it anyway, you will at least need to tell coturn its
    external IP address:

        external-ip=192.88.99.1

    ... and your NAT gateway must forward all of the relayed ports directly
    (eg, port 56789 on the external IP must be always be forwarded to port
    56789 on the internal IP).

    If you get this working, let us know!

1.  (Re)start the turn server:

    * If you used the Debian package (or have set up a systemd unit yourself):
      ```sh
      systemctl restart coturn
      ```

    * If you installed from source:

      ```sh
      bin/turnserver -o
      ```

## Synapse setup

Your home server configuration file needs the following extra keys:

1.  "`turn_uris`": This needs to be a yaml list of public-facing URIs
    for your TURN server to be given out to your clients. Add separate
    entries for each transport your TURN server supports.
2.  "`turn_shared_secret`": This is the secret shared between your
    Home server and your TURN server, so you should set it to the same
    string you used in turnserver.conf.
3.  "`turn_user_lifetime`": This is the amount of time credentials
    generated by your Home Server are valid for (in milliseconds).
    Shorter times offer less potential for abuse at the expense of
    increased traffic between web clients and your home server to
    refresh credentials. The TURN REST API specification recommends
    one day (86400000).
4.  "`turn_allow_guests`": Whether to allow guest users to use the
    TURN server. This is enabled by default, as otherwise VoIP will
    not work reliably for guests. However, it does introduce a
    security risk as it lets guests connect to arbitrary endpoints
    without having gone through a CAPTCHA or similar to register a
    real account.

As an example, here is the relevant section of the config file for `matrix.org`. The
`turn_uris` are appropriate for TURN servers listening on the default ports, with no TLS.

    turn_uris: [ "turn:turn.matrix.org?transport=udp", "turn:turn.matrix.org?transport=tcp" ]
    turn_shared_secret: "n0t4ctuAllymatr1Xd0TorgSshar3d5ecret4obvIousreAsons"
    turn_user_lifetime: 86400000
    turn_allow_guests: True

After updating the homeserver configuration, you must restart synapse:

  * If you use synctl:
    ```sh
    cd /where/you/run/synapse
    ./synctl restart
    ```
  * If you use systemd:
    ```
    systemctl restart synapse.service
    ```
... and then reload any clients (or wait an hour for them to refresh their
settings).

## Troubleshooting

The normal symptoms of a misconfigured TURN server are that calls between
devices on different networks ring, but get stuck at "call
connecting". Unfortunately, troubleshooting this can be tricky.

Here are a few things to try:

 * Check that your TURN server is not behind NAT. As above, we're not aware of
   anyone who has successfully set this up.

 * Check that you have opened your firewall to allow TCP and UDP traffic to the
   TURN ports (normally 3478 and 5479).

 * Check that you have opened your firewall to allow UDP traffic to the UDP
   relay ports (49152-65535 by default).

 * Some WebRTC implementations (notably, that of Google Chrome) appear to get
   confused by TURN servers which are reachable over IPv6 (this appears to be
   an unexpected side-effect of its handling of multiple IP addresses as
   defined by
   [`draft-ietf-rtcweb-ip-handling`](https://tools.ietf.org/html/draft-ietf-rtcweb-ip-handling-12)).

   Try removing any AAAA records for your TURN server, so that it is only
   reachable over IPv4.

 * Enable more verbose logging in coturn via the `verbose` setting:

   ```
   verbose
   ```

   ... and then see if there are any clues in its logs.

 * If you are using a browser-based client under Chrome, check
   `chrome://webrtc-internals/` for insights into the internals of the
   negotiation. On Firefox, check the "Connection Log" on `about:webrtc`.

   (Understanding the output is beyond the scope of this document!)

 * You can test your Matrix homeserver TURN setup with https://test.voip.librepush.net/.
   Note that this test is not fully reliable yet, so don't be discouraged if
   the test fails.
   [Here](https://github.com/matrix-org/voip-tester) is the github repo of the
   source of the tester, where you can file bug reports.

 * There is a WebRTC test tool at
   https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/. To
   use it, you will need a username/password for your TURN server. You can
   either:

    * look for the `GET /_matrix/client/r0/voip/turnServer` request made by a
      matrix client to your homeserver in your browser's network inspector. In
      the response you should see `username` and `password`. Or:

    * Use the following shell commands:

      ```sh
      secret=staticAuthSecretHere

      u=$((`date +%s` + 3600)):test
      p=$(echo -n $u | openssl dgst -hmac $secret -sha1 -binary | base64)
      echo -e "username: $u\npassword: $p"
      ```

      Or:

    * Temporarily configure coturn to accept a static username/password. To do
      this, comment out `use-auth-secret` and `static-auth-secret` and add the
      following:

      ```
      lt-cred-mech
      user=username:password
      ```

      **Note**: these settings will not take effect unless `use-auth-secret`
      and `static-auth-secret` are disabled.

      Restart coturn after changing the configuration file.

      Remember to restore the original settings to go back to testing with
      Matrix clients!

   If the TURN server is working correctly, you should see at least one `relay`
   entry in the results.
