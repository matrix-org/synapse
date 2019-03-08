Setting up Federation
=====================

Federation is the process by which users on different servers can participate
in the same room. For this to work, those other servers must be able to contact
yours to send messages.

The ``server_name`` configured in the Synapse configuration file (often
``homeserver.yaml``) defines how resources (users, rooms,...) will be
identified (ie: ``@user:example.com``, ``#room:example.com``). By
default, it is also the default domain that other servers will use to
try to reach your server via port 8448. This is easy to set
up and will work provided you set the ``server_name`` to match your
machine's public DNS hostname, and provide Synapse with a TLS certificate
which is valid for your ``server_name``.

For a more flexible configuration, you can have ``server_name``
resources (ie: ``@user:example.com``) served by a different host and
port (ie: ``synapse.example.com:443``). There are two ways to do this:

- adding a DNS ``SRV`` record in the DNS zone of domain
  ``example.com``. Beware that this method has some limitations as it
  will still require your delegated server to use a SSL certificate
  identifying it as the original ``server_name`` domain name. Meaning
  that the provided ``synapse.example.com`` delegate domain name will
  only be used to get a possibly different IP/port, but won't be used
  for SSL domain name verification.

- adding a ``/.well-known/matrix/server`` URL served on ``https://example.com``.

For both methods let's say you want to run your server at
``synapse.example.com`` on port ``443`` (instead of ``8448``), but you
want to have your Matrix user-ids look like ``@user:example.com``.

Without configuring delegation, the matrix federation will
expect to find your resources via ``example.com:8448``. The
following methods allow you to provide a different server and port for
``*:example.com`` resources.

If all goes well, you should be able to [connect to your server with a client](../README.rst#registering-a-new-user-from-a-client).
and then join a room via federation. (A good place to start is ``#synapse:matrix.org`` - a room for 
Synapse admins.)


DNS SRV delegation
------------------

To use this method, you need to have write access to your
``server_name`` 's domain zone DNS records (in our example it would be
``example.com`` DNS zone).

This method requires the target server to provide a
valid SSL certificate identifying it as the original ``server_name``
domain zone. So the delegate domain name is only used to resolve a possible 
different IP/Port combination to find your server. You must use the other 
delegation method if this isn't what you want. (for more details on the 
rationale [see here](https://github.com/matrix-org/matrix-doc/blob/master/proposals/1711-x509-for-federation.md#interaction-with-srv-records))

You need to add a SRV record in your ``server_name`` 's DNS zone with
this format::

     _matrix._tcp.<yourdomain.com> <ttl> IN SRV <priority> <weight> <port> <synapse.server.name>

In our example, we would need to add this SRV record in the
``example.com`` DNS zone::

     _matrix._tcp.example.com. 3600 IN SRV 10 5 443 synapse.example.com.


Once done and set up, you can check the DNS record with ``dig -t srv
_matrix._tcp.<server_name>``, in our example, we would expect this::

    $ dig -t srv _matrix._tcp.example.com
    _matrix._tcp.example.com. 3600    IN      SRV     10 0 443 synapse.example.com.

Note that the server host name cannot be an alias (CNAME record): it has to point
directly to the server hosting the synapse instance.


.well-known delegation
----------------------

To use this method, you need to be able to alter the
``server_name`` 's https server to serve the ``/.well-known/matrix/server`` 
URL. Having an active server (with a valid ``SSL`` certificate) serving your 
``server_name`` domain is out of the scope of this documentation.

The URL ``https://<server_name>/.well-known/matrix/server`` should
return a JSON structure containing the key ``m.server`` like so::

    {
	    "m.server": "<synapse.server.name>:<yourport>"
    }

In our example, this would mean that URL ``https://example.com/.well-known/matrix/server``
should return::

    {
	    "m.server": "synapse.example.com:443"
    }

This delegation method allows a full delegation contrary to the DNS SRV
method: federation servers will contact the given hostname's IP and
will check for a valid SSL certificate on the same delegated hostname (in our
example: ``synapse.example.com``).


Setting your server_name
------------------------

Note that you can NOT change the ``server_name`` after the database
is first created.  So choose your ``server_name`` with care.

You can then configure your homeserver to use ``<yourdomain.com>`` as the domain in
its user-ids, by setting ``server_name`` on the command line::

    python -m synapse.app.homeserver \
        --server-name <yourdomain.com> \
        --config-path homeserver.yaml \
        --generate-config
    python -m synapse.app.homeserver --config-path homeserver.yaml

If you've already generated the config file, you need to edit the ``server_name``
in your configuration file (often ``homeserver.yaml`` file). If you have 
already started Synapse and a database has been created, you will need to 
recreate the database.


Troubleshooting
---------------

You can use the [federation tester](
<https://matrix.org/federationtester>) to check if your homeserver is
configured correctly. Or the [raw API url used by the federation tester](https://matrix.org/federationtester/api/report?server_name=DOMAIN)
, note that you'll have to modify this URL to replace ``DOMAIN`` with your
``server_name``. Hitting the URL directly provides extra detail.

For more details the see the [Server to Server Spec](https://matrix.org/docs/spec/server_server/r0.1.1.html#resolving-server-names).

The typical failure mode for federation is that when the server tries to join 
a room, it is rejected with "401: Unauthorized". Generally this means that other
servers in the room could not access yours. (Joining a room over federation is 
a complicated dance which requires connections in both directions).

Another common problem is that people on other servers can't join rooms that
you invite them to. This can be caused by an incorrectly-configured reverse
proxy: see [reverse_proxy.rst](<reverse_proxy.rst>) for instructions on how to correctly
configure a reverse proxy.


Running a Demo Federation of Synapses
-------------------------------------

If you want to get up and running quickly with a trio of homeservers in a
private federation, there is a script in the ``demo`` directory. This is mainly
useful just for development purposes. See [demo/README](<../demo/README>).
