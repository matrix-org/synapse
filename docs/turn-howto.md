# Overview

This document explains how to enable VoIP relaying on your Home Server with TURN.

The synapse Matrix Home Server supports integration with [TURN](<https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT>) server via the
[TURN server REST API](<http://tools.ietf.org/html/draft-uberti-behave-turn-rest-00>).
This allows the Home Server to generate credentials that are valid for use on the
TURN server through the use of a secret shared between the Home Server and
the TURN server.

The following sections describe how to install [coturn](<https://github.com/coturn/coturn>) (which implements the TURN REST API) and integrate it with synapse.

# Requirements
For TURN to work, the service must be reachable on a public IP. TURN acts as the
"media anchor" to allow NATted clients to exchange media streams (voice / video)
via a commonly reachable point on the Internet.

Hosting TURN behind NAT requires careful planning of port-fowarding and firewall
configuration. Due to the possible security implications and complexity, a good
understanding of the TURN protocol is recommended.

# Installation
`Coturn` is available from a variety of sources such as native package managers,
docker images or installation from source. For our application no supporting
services (DB) or persistent storage is required other than for logs and config.

## `Coturn` Setup

#### Debian installation

    # apt install coturn

#### Source installation

1. Download the [latest release](https://github.com/coturn/coturn/releases/latest) from github.  Unpack it and `cd` into the directory.

1.  Configure it:

        ./configure

    > You may need to install `libevent2`: if so, you should do so in
    > the way recommended by your operating system. You can ignore
    > warnings about lack of database support: a database is unnecessary
    > for this purpose.

1.  Build and install it:

        make
        make install

#### Docker installation
There are coturn docker images available. You can prepare by running

        docker pull instrumentisto/coturn

The first part of the command needed to start your container detached is as follows:

        docker run -d -p 3478:3478/udp -p 3478:3478/tcp \
        -p <range_start-range_end:range_start-range_end>/udp \
        --name="<fill in container name for easy access in CLI>" \
        -v /etc/localtime:/etc/localtime:ro \
        --mount type=tmpfs,destination=/var/lib/coturn \
        --restart=unless-stopped instrumentisto/coturn

With the first -p option we expose the TURN port on both TCP and UDP. The second
-p option specifies the UDP port range used for media bridging (where your clients
will send media streams). The temp mount is to store run state of the deamon.
See Docker documentation for details.

For Docker all coturn configuration options listed below can also be specified
on the docker startup script, like this:

        [... same as above to start ...]
        --restart=unless-stopped instrumentisto/coturn \
        --total-quota=1200 --realm=<your turn server domain, ie turn.domain.tld> \
        --external-ip='$(detect-external-ip)'

So any configuration option described below you can add after the docker image
name, preceeded by --. You can also mount a volume with -v and place a
configuration file there, for example turnserver.conf.


### Configuration

1.  Create or edit the config file in `/etc/turnserver.conf`. The relevant
    lines, with example values, are:

        use-auth-secret
        static-auth-secret=<your secret key here>
        realm=turn.myserver.org
        external-ip='$(detect-external-ip)'
        no-cli

    The 'external-ip' can either be the included detection script like this example
    or the real external IP. That IP can be different from the local / relay IP, which
    is auto detected and not specified.

    See `turnserver.conf` for explanations of the options. One way to generate
    the `static-auth-secret` is with `pwgen`:

        pwgen -s 64 1

1.  Consider your security settings. TURN lets users request a relay which will
    connect to arbitrary IP addresses and ports. The following configuration is
    suggested as a minimum starting point:
    
        # VoIP traffic is all UDP. There is no reason to let users connect to arbitrary TCP endpoints
        # via the relay.
        no-tcp-relay
        # Require authentication (same as for TURN) for STUN requests to preven refrection attacks
        # via the STUN mechanism.
        secure-stun
        # Disable multicast peers, to prevent multicast traffic.
        no-multicast-peers
        # Use / add fingerprint attribute in TURN messages.
        fingerprint
        
        # Specify a dededicated port-range to relay media streams on (n this exmaple 400 ports)
        min-port=49100
        max-port=49500

        # don't let the relay ever try to connect to private IP address ranges within your network (if any)
        # given the turn server is likely behind your firewall, remember to include any privileged public IPs too.
        denied-peer-ip=10.0.0.0-10.255.255.255
        denied-peer-ip=192.168.0.0-192.168.255.255
        denied-peer-ip=172.16.0.0-172.31.255.255
        
        # special case the turn server itself so that client->TURN->TURN->client flows work
        allowed-peer-ip=10.0.0.1
        
        # allow LAN clients, in order to allow for your clients to be either outside your network or inside.
        # In the example below it's a range of 100 IPs (the DHCP range normally)
        # It's important to NOT allow the LAN clients unless you have authentication configured!
        allowed-peer-ip=192.168.1.100-192.168.1.200
        
        # consider whether you want to limit the quota of relayed streams per user (or total) to avoid risk of DoS.
        user-quota=12 # 4 streams per video call, so 12 streams = 3 simultaneous relayed calls per user.
        total-quota=1200 #total number of simultaneous calls

1.  Ensure your firewall allows traffic into the TURN server on the ports
    you've configured it to listen on (remember to allow both TCP and UDP TURN
    traffic), in this example 3478 (both UDP and TCP).
    Also allows UDP traffic on the specified port-range, in this example 49100-49500.

1.  If you've configured coturn to support TLS/DTLS, generate or import your
    private key and certificate.

## synapse Setup

Your home server configuration file needs the following extra keys:

1.  "`turn_uris`": This needs to be a yaml list of public-facing URIs
    for your TURN server to be given out to your clients. Add separate
    entries for each transport your TURN server supports.
2.  "`turn_shared_secret`": This is the secret shared between your
    Home server and your TURN server, so you should set it to the same
    string you used in turnserver.conf. This secret is used to created
    temporary credentials for clients to use TURN.
3.  "`turn_user_lifetime`": This is the amount of time credentials
    generated by your Home Server are valid for (in milliseconds).
    Shorter times offer less potential for abuse at the expense of
    increased traffic between web clients and your home server to
    refresh credentials. The TURN REST API specification recommends
    one day (86400000).
4.  "`turn_allow_guests`": Whether to allow guest users to use the
    TURN server. This is enabled by default, as otherwise VoIP will
    not work reliably for voip calls between federated servers.
    However, it does introduce a security risk as it lets guests
    connect to arbitrary endpoints without having gone through a
    CAPTCHA or similar to register a real account.

As an example, here is the relevant section of the config file for matrix.org:

    turn_uris: [ "turn:turn.matrix.org:3478?transport=udp", "turn:turn.matrix.org:3478?transport=tcp" ]
    turn_shared_secret: n0t4ctuAllymatr1Xd0TorgSshar3d5ecret4obvIousreAsons
    turn_user_lifetime: 86400000
    turn_allow_guests: True

After updating the homeserver configuration, you must restart synapse:

    cd /where/you/run/synapse
    ./synctl restart

..and your Home Server now supports VoIP relaying!


# Troubleshooting

1. Start with disabling the client setting "Use fallback Voip server"
   to make sure you're using your own TURN server.
2. Clear client caches
3. Run the TURN server with the 'verbose' option to get more verbose
   logging and check what's happening
4. Last resort is always running a tcpdump on the TURN server with
   a udp filter and follow traffic flows (both control on 3478 as
   well as media streams)