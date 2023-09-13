# Overview

This document explains how to enable VoIP relaying on your homeserver with
TURN.

The synapse Matrix homeserver supports integration with TURN server via the
[TURN server REST API](<https://tools.ietf.org/html/draft-uberti-behave-turn-rest-00>). This
allows the homeserver to generate credentials that are valid for use on the
TURN server through the use of a secret shared between the homeserver and the
TURN server.

This documentation provides two TURN server configuration examples:

* [coturn](setup/turn/coturn.md)
* [eturnal](setup/turn/eturnal.md)

## Requirements

For TURN relaying to work, the TURN service must be hosted on a server/endpoint with a public IP.

Hosting TURN behind NAT requires port forwarding and for the NAT gateway to have a public IP.
However, even with appropriate configuration, NAT is known to cause issues and to often not work.

Afterwards, the homeserver needs some further configuration.

## Synapse setup

Your homeserver configuration file needs the following extra keys:

1.  [`turn_uris`](usage/configuration/config_documentation.md#turn_uris)
2.  [`turn_shared_secret`](usage/configuration/config_documentation.md#turn_shared_secret)
3.  [`turn_user_lifetime`](usage/configuration/config_documentation.md#turn_user_lifetime)
4.  [`turn_allow_guests`](usage/configuration/config_documentation.md#turn_allow_guests)

As an example, here is the relevant section of the config file for `matrix.org`. The
`turn_uris` are appropriate for TURN servers listening on the default ports, with no TLS.

    turn_uris: [ "turn:turn.matrix.org?transport=udp", "turn:turn.matrix.org?transport=tcp" ]
    turn_shared_secret: "n0t4ctuAllymatr1Xd0TorgSshar3d5ecret4obvIousreAsons"
    turn_user_lifetime: 86400000
    turn_allow_guests: true

After updating the homeserver configuration, you must restart synapse:

  * If you use synctl:
    ```sh
    # Depending on how Synapse is installed, synctl may already be on
    # your PATH. If not, you may need to activate a virtual environment.
    synctl restart
    ```
  * If you use systemd:
    ```sh
    systemctl restart matrix-synapse.service
    ```
... and then reload any clients (or wait an hour for them to refresh their
settings).

## Troubleshooting

The normal symptoms of a misconfigured TURN server are that calls between
devices on different networks ring, but get stuck at "call
connecting". Unfortunately, troubleshooting this can be tricky.

Here are a few things to try:

 * Check that you have opened your firewall to allow TCP and UDP traffic to the
   TURN ports (normally 3478 and 5349).

 * Check that you have opened your firewall to allow UDP traffic to the UDP
   relay ports (49152-65535 by default).

 * Try disabling TLS/DTLS listeners and enable only its (unencrypted)
   TCP/UDP listeners. (This will only leave signaling traffic unencrypted;
   voice & video WebRTC traffic is always encrypted.)

 * Some WebRTC implementations (notably, that of Google Chrome) appear to get
   confused by TURN servers which are reachable over IPv6 (this appears to be
   an unexpected side-effect of its handling of multiple IP addresses as
   defined by
   [`draft-ietf-rtcweb-ip-handling`](https://tools.ietf.org/html/draft-ietf-rtcweb-ip-handling-12)).

   Try removing any AAAA records for your TURN server, so that it is only
   reachable over IPv4.

 * If your TURN server is behind NAT:

    * double-check that your NAT gateway is correctly forwarding all TURN
      ports (normally 3478 & 5349 for TCP & UDP TURN traffic, and 49152-65535 for the UDP
      relay) to the NAT-internal address of your TURN server. If advertising
      both IPv4 and IPv6 external addresses via the `external-ip` option, ensure
      that the NAT is forwarding both IPv4 and IPv6 traffic to the IPv4 and IPv6
      internal addresses of your TURN server. When in doubt, remove AAAA records
      for your TURN server and specify only an IPv4 address as your `external-ip`.

    * ensure that your TURN server uses the NAT gateway as its default route.

 * Enable more verbose logging, in `coturn` via the `verbose` setting:

   ```
   verbose
   ```

    or with `eturnal` with the shell command `eturnalctl loglevel debug` or in the configuration file (the service needs to [reload](https://eturnal.net/documentation/#Operation) for it to become effective):

    ```yaml
        ## Logging configuration:
            log_level: debug
    ```

   ... and then see if there are any clues in its logs.

 * If you are using a browser-based client under Chrome, check
   `chrome://webrtc-internals/` for insights into the internals of the
   negotiation. On Firefox, check the "Connection Log" on `about:webrtc`.

   (Understanding the output is beyond the scope of this document!)

 * You can test your Matrix homeserver TURN setup with <https://test.voip.librepush.net/>.
   Note that this test is not fully reliable yet, so don't be discouraged if
   the test fails.
   [Here](https://github.com/matrix-org/voip-tester) is the github repo of the
   source of the tester, where you can file bug reports.

 * There is a WebRTC test tool at
   <https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/>. To
   use it, you will need a username/password for your TURN server. You can
   either:

    * look for the `GET /_matrix/client/r0/voip/turnServer` request made by a
      matrix client to your homeserver in your browser's network inspector. In
      the response you should see `username` and `password`. Or:

    * Use the following shell commands for `coturn`:

      ```sh
      secret=staticAuthSecretHere

      u=$((`date +%s` + 3600)):test
      p=$(echo -n $u | openssl dgst -hmac $secret -sha1 -binary | base64)
      echo -e "username: $u\npassword: $p"
      ```

      or for `eturnal`

      ```sh
      eturnalctl credentials
      ```
      

    * Or (**coturn only**): Temporarily configure `coturn` to accept a static
      username/password. To do this, comment out `use-auth-secret` and
      `static-auth-secret` and add the following:

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
