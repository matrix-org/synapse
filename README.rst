.. contents::

Introduction
============

Matrix is an ambitious new ecosystem for open federated Instant Messaging and
VoIP.  The basics you need to know to get up and running are:

- Everything in Matrix happens in a room.  Rooms are distributed and do not
  exist on any single server.  Rooms can be located using convenience aliases
  like ``#matrix:matrix.org`` or ``#test:localhost:8448``.

- Matrix user IDs look like ``@matthew:matrix.org`` (although in the future
  you will normally refer to yourself and others using a third party identifier
  (3PID): email address, phone number, etc rather than manipulating Matrix user IDs)

The overall architecture is::

      client <----> homeserver <=====================> homeserver <----> client
             https://somewhere.org/_matrix      https://elsewhere.net/_matrix

``#matrix:matrix.org`` is the official support room for Matrix, and can be
accessed by any client from https://matrix.org/docs/projects/try-matrix-now.html or
via IRC bridge at irc://irc.freenode.net/matrix.

Synapse is currently in rapid development, but as of version 0.5 we believe it
is sufficiently stable to be run as an internet-facing service for real usage!

About Matrix
============

Matrix specifies a set of pragmatic RESTful HTTP JSON APIs as an open standard,
which handle:

- Creating and managing fully distributed chat rooms with no
  single points of control or failure
- Eventually-consistent cryptographically secure synchronisation of room
  state across a global open network of federated servers and services
- Sending and receiving extensible messages in a room with (optional)
  end-to-end encryption[1]
- Inviting, joining, leaving, kicking, banning room members
- Managing user accounts (registration, login, logout)
- Using 3rd Party IDs (3PIDs) such as email addresses, phone numbers,
  Facebook accounts to authenticate, identify and discover users on Matrix.
- Placing 1:1 VoIP and Video calls

These APIs are intended to be implemented on a wide range of servers, services
and clients, letting developers build messaging and VoIP functionality on top
of the entirely open Matrix ecosystem rather than using closed or proprietary
solutions. The hope is for Matrix to act as the building blocks for a new
generation of fully open and interoperable messaging and VoIP apps for the
internet.

Synapse is a reference "homeserver" implementation of Matrix from the core
development team at matrix.org, written in Python/Twisted.  It is intended to
showcase the concept of Matrix and let folks see the spec in the context of a
codebase and let you run your own homeserver and generally help bootstrap the
ecosystem.

In Matrix, every user runs one or more Matrix clients, which connect through to
a Matrix homeserver. The homeserver stores all their personal chat history and
user account information - much as a mail client connects through to an
IMAP/SMTP server. Just like email, you can either run your own Matrix
homeserver and control and own your own communications and history or use one
hosted by someone else (e.g. matrix.org) - there is no single point of control
or mandatory service provider in Matrix, unlike WhatsApp, Facebook, Hangouts,
etc.

We'd like to invite you to join #matrix:matrix.org (via
https://matrix.org/docs/projects/try-matrix-now.html), run a homeserver, take a look
at the `Matrix spec <https://matrix.org/docs/spec>`_, and experiment with the
`APIs <https://matrix.org/docs/api>`_ and `Client SDKs
<https://matrix.org/docs/projects/try-matrix-now.html#client-sdks>`_.

Thanks for using Matrix!

[1] End-to-end encryption is currently in beta: `blog post <https://matrix.org/blog/2016/11/21/matrixs-olm-end-to-end-encryption-security-assessment-released-and-implemented-cross-platform-on-riot-at-last>`_.


Synapse Installation
====================

For details on how to install synapse, see `<INSTALL.md>`_.


Connecting to Synapse from a client
===================================

The easiest way to try out your new Synapse installation is by connecting to it
from a web client.

Unless you are running a test instance of Synapse on your local machine, in
general, you will need to enable TLS support before you can successfully
connect from a client: see `<INSTALL.md#tls-certificates>`_.

An easy way to get started is to login or register via Riot at 
https://riot.im/app/#/login or https://riot.im/app/#/register respectively. 
You will need to change the server you are logging into from ``matrix.org``
and instead specify a Homeserver URL of ``https://<server_name>:8448`` 
(or just ``https://<server_name>`` if you are using a reverse proxy). 
(Leave the identity server as the default - see `Identity servers`_.) 
If you prefer to use another client, refer to our 
`client breakdown <https://matrix.org/docs/projects/clients-matrix>`_.

If all goes well you should at least be able to log in, create a room, and
start sending messages.

.. _`client-user-reg`:

Registering a new user from a client
------------------------------------

By default, registration of new users via Matrix clients is disabled. To enable
it, specify ``enable_registration: true`` in ``homeserver.yaml``. (It is then
recommended to also set up CAPTCHA - see `<docs/CAPTCHA_SETUP.rst>`_.)

Once ``enable_registration`` is set to ``true``, it is possible to register a
user via `riot.im <https://riot.im/app/#/register>`_ or other Matrix clients.

Your new user name will be formed partly from the ``server_name`` (see
`Configuring synapse`_), and partly from a localpart you specify when you
create the account. Your name will take the form of::

    @localpart:my.domain.name

(pronounced "at localpart on my dot domain dot name").

As when logging in, you will need to specify a "Custom server".  Specify your
desired ``localpart`` in the 'User name' box.

ACME setup
==========

For details on having Synapse manage your federation TLS certificates
automatically, please see `<docs/ACME.md>`_.


Security Note
=============

Matrix serves raw user generated data in some APIs - specifically the `content
repository endpoints <https://matrix.org/docs/spec/client_server/latest.html#get-matrix-media-r0-download-servername-mediaid>`_.

Whilst we have tried to mitigate against possible XSS attacks (e.g.
https://github.com/matrix-org/synapse/pull/1021) we recommend running
matrix homeservers on a dedicated domain name, to limit any malicious user generated
content served to web browsers a matrix API from being able to attack webapps hosted
on the same domain.  This is particularly true of sharing a matrix webclient and
server on the same domain.

See https://github.com/vector-im/riot-web/issues/1977 and
https://developer.github.com/changes/2014-04-25-user-content-security for more details.

Troubleshooting
===============

Running out of File Handles
---------------------------

If synapse runs out of filehandles, it typically fails badly - live-locking
at 100% CPU, and/or failing to accept new TCP connections (blocking the
connecting client).  Matrix currently can legitimately use a lot of file handles,
thanks to busy rooms like #matrix:matrix.org containing hundreds of participating
servers.  The first time a server talks in a room it will try to connect
simultaneously to all participating servers, which could exhaust the available
file descriptors between DNS queries & HTTPS sockets, especially if DNS is slow
to respond.  (We need to improve the routing algorithm used to be better than
full mesh, but as of June 2017 this hasn't happened yet).

If you hit this failure mode, we recommend increasing the maximum number of
open file handles to be at least 4096 (assuming a default of 1024 or 256).
This is typically done by editing ``/etc/security/limits.conf``

Separately, Synapse may leak file handles if inbound HTTP requests get stuck
during processing - e.g. blocked behind a lock or talking to a remote server etc.
This is best diagnosed by matching up the 'Received request' and 'Processed request'
log lines and looking for any 'Processed request' lines which take more than
a few seconds to execute.  Please let us know at #synapse:matrix.org if
you see this failure mode so we can help debug it, however.

Help!! Synapse eats all my RAM!
-------------------------------

Synapse's architecture is quite RAM hungry currently - we deliberately
cache a lot of recent room data and metadata in RAM in order to speed up
common requests.  We'll improve this in future, but for now the easiest
way to either reduce the RAM usage (at the risk of slowing things down)
is to set the almost-undocumented ``SYNAPSE_CACHE_FACTOR`` environment
variable.  The default is 0.5, which can be decreased to reduce RAM usage
in memory constrained enviroments, or increased if performance starts to
degrade.

Using `libjemalloc <http://jemalloc.net/>`_ can also yield a significant
improvement in overall amount, and especially in terms of giving back RAM
to the OS. To use it, the library must simply be put in the LD_PRELOAD
environment variable when launching Synapse. On Debian, this can be done
by installing the ``libjemalloc1`` package and adding this line to
``/etc/default/matrix-synapse``::

    LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.1

This can make a significant difference on Python 2.7 - it's unclear how
much of an improvement it provides on Python 3.x.

Upgrading an existing Synapse
=============================

The instructions for upgrading synapse are in `UPGRADE.rst`_.
Please check these instructions as upgrading may require extra steps for some
versions of synapse.

.. _UPGRADE.rst: UPGRADE.rst

.. _federation:

Setting up Federation
=====================

Federation is the process by which users on different servers can participate
in the same room. For this to work, those other servers must be able to contact
yours to send messages.

The ``server_name`` configured in synapse configuration file (often
``homeserver.yaml``) defines how resources (users, rooms,...) will be
identified (ie: ``@user:example.com``, ``#room:example.com``). By
default, it is also the default domain that other servers will use to
try to reach your server, and they'll try to connect on
port 8448. This is easy to set up and will work provided you set the
``server_name`` to match your machine's public DNS hostname, and give
Synapse a TLS certificate which is valid for your ``server_name``.

For a more flexible configuration, you can have ``server_name``
resources (ie: ``@user:example.com``) served by a different host and
port (ie: ``synapse.example.com:443``). There are 2 ways to do that:

- adding a ``/.well-known/matrix/server`` URL served on ``https://example.com``

- adding a DNS ``SRV`` record in DNS zone of domain
  ``èxample.com``. Beware that this method has some limitation as it
  will still require your delegated server to use a SSL certification
  identifying him as the original ``server_name`` domain name. Meaning
  that the provided ``synapse.example.com`` delegate domain name will
  only be used to get a possibly different IP/port, but won't be used
  for SSL domain name verification.

For both method let's say you want to run your server at
``synapse.example.com`` on port ``443`` (instead of ``8448``), but you
want to have your Matrix user-ids look like ``@user:example.com``.

Without any of these delegation method, the matrix federation will
expect to find your resources through ``example.com:8448``. These
following method allows you to provide a different server and port for
``*:example.com`` resources.

If all goes well, you should be able to `connect to your server with a client`__,
and then join a room via federation. (Try ``#matrix-dev:matrix.org`` as a first
step. "Matrix HQ"'s sheer size and activity level tends to make even the
largest boxes pause for thought.)

.. __: `Connecting to Synapse from a client`_

DNS SRV delegation method
-------------------------

To use this method, you need to have write access to your
``server_name`` 's domain zone DNS records (in our example it would be
``example.com`` DNS zone).

This method additionally requires your delegate server to provide a
valid SSL certificate identifying him on the original ``server_name``
domain zone.  So with this method the delegate domain name is only
used to resolve a possible different IP/Port combination to find your
server. You must use the other delegation method is this isn't what
you want. (here are `the rationale about this behavior <https://github.com/matrix-org/matrix-doc/blob/master/proposals/1711-x509-for-federation.md#interaction-with-srv-records>`_)

You need to add a SRV record in your ``server_name`` 's DNS zone with
this format::

     _matrix._tcp.<yourdomain.com> <ttl> IN SRV 10 0 <port> <synapse.server.name>

In our example, we would need to add this SRV record in the
``example.com`` DNS zone::

     _matrix._tcp.example.com. 3600 IN SRV 10 0 443 synapse.example.com.


Once done and set up, you can check the DNS record with ``dig -t srv
_matrix._tcp.<server_name>``, in our example, we would expect this::

    $ dig -t srv _matrix._tcp.example.com
    _matrix._tcp.example.com. 3600    IN      SRV     10 0 443 synapse.example.com.

Note that the server host name cannot be an alias (CNAME record): it has to point
directly to the server hosting the synapse instance.


.well-known delegation method
-----------------------------

To use this method, you need to be able to alter the
``server_name`` 's https server to make him serve the
``/.well-known/matrix/server`` URL. Having an active server (with
correct ``SSL`` certificate) serving your ``server_name`` domain is
out of the scope of this documentation.

The URL ``https://<server_name>/.well-known/matrix/server`` should 
return a JSON structure containing the key ``m.server`` as this::

    {
	    "m.server": "<synapse.server.name>:<yourport>"
    }

In our example, this would mean that URL ``https://example.com/.well-known/matrix/server``
should return this::

    {
	    "m.server": "synapse.example.com:443"
    }

This delegation method allow a full delegation contrary to the DNS SRV
method: federation servers will contact the given hostname's IP and
will check for a valid SSL on the same delegated hostname (in our
example: ``synapse.example.com``).


Setting your server_name
------------------------

Note that you can NOT change the ``server_name`` after the database
was first created.  So choose your ``server_name`` with care.

You can then configure your homeserver to use ``<yourdomain.com>`` as the domain in
its user-ids, by setting ``server_name`` on the command line::

    python -m synapse.app.homeserver \
        --server-name <yourdomain.com> \
        --config-path homeserver.yaml \
        --generate-config
    python -m synapse.app.homeserver --config-path homeserver.yaml

If you've already generated the config file, you need to edit the ``server_name``
in your configuration file (often ``homeserver.yaml`` file). If you've already started Synapse and a
database has been created, you will have to recreate the database.


Troubleshooting
---------------

You can use the `federation tester
<https://matrix.org/federationtester>`_ to check if your homeserver is
all set. Or the `raw API url used by the federation tester
<https://matrix.org/federationtester/api/report?server_name=DOMAIN>`_
, note that you'll have to modify this URL to replace ``DOMAIN`` with your
``server_name``. The last URL will serve raw JSON that is often more
difficult to interpret but also way more complete.

The `complete server to server spec about this mecanism
<https://matrix.org/docs/spec/server_server/r0.1.1.html#resolving-server-names>`_
is available here if you want more details.

The typical failure mode with federation is that when you try to join a room,
it is rejected with "401: Unauthorized". Generally this means that other
servers in the room couldn't access yours. (Joining a room over federation is a
complicated dance which requires connections in both directions).

Another common problem is that people on other servers can't join rooms that
you invite them to. This can be caused by an incorrectly-configured reverse
proxy: see `<docs/reverse_proxy.rst>`_ for instructions on how to correctly
configure a reverse proxy.


Running a Demo Federation of Synapses
-------------------------------------

If you want to get up and running quickly with a trio of homeservers in a
private federation, there is a script in the ``demo`` directory. This is mainly
useful just for development purposes. See `<demo/README>`_.


Using PostgreSQL
================

As of Synapse 0.9, `PostgreSQL <https://www.postgresql.org>`_ is supported as an
alternative to the `SQLite <https://sqlite.org/>`_ database that Synapse has
traditionally used for convenience and simplicity.

The advantages of Postgres include:

* significant performance improvements due to the superior threading and
  caching model, smarter query optimiser
* allowing the DB to be run on separate hardware
* allowing basic active/backup high-availability with a "hot spare" synapse
  pointing at the same DB master, as well as enabling DB replication in
  synapse itself.

For information on how to install and use PostgreSQL, please see
`docs/postgres.rst <docs/postgres.rst>`_.

.. _reverse-proxy:

Using a reverse proxy with Synapse
==================================

It is recommended to put a reverse proxy such as
`nginx <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>`_,
`Apache <https://httpd.apache.org/docs/current/mod/mod_proxy_http.html>`_,
`Caddy <https://caddyserver.com/docs/proxy>`_ or
`HAProxy <https://www.haproxy.org/>`_ in front of Synapse. One advantage of
doing so is that it means that you can expose the default https port (443) to
Matrix clients without needing to run Synapse with root privileges.

For information on configuring one, see `<docs/reverse_proxy.rst>`_.

Identity Servers
================

Identity servers have the job of mapping email addresses and other 3rd Party
IDs (3PIDs) to Matrix user IDs, as well as verifying the ownership of 3PIDs
before creating that mapping.

**They are not where accounts or credentials are stored - these live on home
servers. Identity Servers are just for mapping 3rd party IDs to matrix IDs.**

This process is very security-sensitive, as there is obvious risk of spam if it
is too easy to sign up for Matrix accounts or harvest 3PID data. In the longer
term, we hope to create a decentralised system to manage it (`matrix-doc #712
<https://github.com/matrix-org/matrix-doc/issues/712>`_), but in the meantime,
the role of managing trusted identity in the Matrix ecosystem is farmed out to
a cluster of known trusted ecosystem partners, who run 'Matrix Identity
Servers' such as `Sydent <https://github.com/matrix-org/sydent>`_, whose role
is purely to authenticate and track 3PID logins and publish end-user public
keys.

You can host your own copy of Sydent, but this will prevent you reaching other
users in the Matrix ecosystem via their email address, and prevent them finding
you. We therefore recommend that you use one of the centralised identity servers
at ``https://matrix.org`` or ``https://vector.im`` for now.

To reiterate: the Identity server will only be used if you choose to associate
an email address with your account, or send an invite to another user via their
email address.


Password reset
==============

If a user has registered an email address to their account using an identity
server, they can request a password-reset token via clients such as Riot.

A manual password reset can be done via direct database access as follows.

First calculate the hash of the new password::

    $ ~/synapse/env/bin/hash_password
    Password:
    Confirm password:
    $2a$12$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Then update the `users` table in the database::

    UPDATE users SET password_hash='$2a$12$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
        WHERE name='@test:test.com';


Synapse Development
===================

Before setting up a development environment for synapse, make sure you have the
system dependencies (such as the python header files) installed - see
`Installing from source <INSTALL.md#installing-from-source>`_.

To check out a synapse for development, clone the git repo into a working
directory of your choice::

    git clone https://github.com/matrix-org/synapse.git
    cd synapse

Synapse has a number of external dependencies, that are easiest
to install using pip and a virtualenv::

    virtualenv -p python3 env
    source env/bin/activate
    python -m pip install -e .[all]

This will run a process of downloading and installing all the needed
dependencies into a virtual env.

Once this is done, you may wish to run Synapse's unit tests, to
check that everything is installed as it should be::

    python -m twisted.trial tests

This should end with a 'PASSED' result::

    Ran 143 tests in 0.601s

    PASSED (successes=143)

Running the Integration Tests
=============================

Synapse is accompanied by `SyTest <https://github.com/matrix-org/sytest>`_,
a Matrix homeserver integration testing suite, which uses HTTP requests to
access the API as a Matrix client would. It is able to run Synapse directly from
the source tree, so installation of the server is not required.

Testing with SyTest is recommended for verifying that changes related to the
Client-Server API are functioning correctly. See the `installation instructions
<https://github.com/matrix-org/sytest#installing>`_ for details.

Building Internal API Documentation
===================================

Before building internal API documentation install sphinx and
sphinxcontrib-napoleon::

    pip install sphinx
    pip install sphinxcontrib-napoleon

Building internal API documentation::

    python setup.py build_sphinx
