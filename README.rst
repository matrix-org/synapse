================
Synapse |shield|
================

.. |shield| image:: https://img.shields.io/matrix/synapse:matrix.org?label=support&logo=matrix
  :alt: (get support on #synapse:matrix.org)
  :target: https://matrix.to/#/#synapse:matrix.org

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


Support
=======

For support installing or managing Synapse, please join |room|_ (from a matrix.org
account if necessary) and ask questions there. We do not use GitHub issues for
support requests, only for bug reports and feature requests.

.. |room| replace:: ``#synapse:matrix.org``
.. _room: https://matrix.to/#/#synapse:matrix.org


Synapse Installation
====================

.. _federation:

* For details on how to install synapse, see `<INSTALL.md>`_.
* For specific details on how to configure Synapse for federation see `docs/federate.md <docs/federate.md>`_


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
recommended to also set up CAPTCHA - see `<docs/CAPTCHA_SETUP.md>`_.)

Once ``enable_registration`` is set to ``true``, it is possible to register a
user via `riot.im <https://riot.im/app/#/register>`_ or other Matrix clients.

Your new user name will be formed partly from the ``server_name``, and partly
from a localpart you specify when you create the account. Your name will take
the form of::

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


Upgrading an existing Synapse
=============================

The instructions for upgrading synapse are in `UPGRADE.rst`_.
Please check these instructions as upgrading may require extra steps for some
versions of synapse.

.. _UPGRADE.rst: UPGRADE.rst


Using PostgreSQL
================

Synapse offers two database engines:
 * `SQLite <https://sqlite.org/>`_
 * `PostgreSQL <https://www.postgresql.org>`_

By default Synapse uses SQLite in and doing so trades performance for convenience.
SQLite is only recommended in Synapse for testing purposes or for servers with
light workloads.

Almost all installations should opt to use PostreSQL. Advantages include:

* significant performance improvements due to the superior threading and
  caching model, smarter query optimiser
* allowing the DB to be run on separate hardware
* allowing basic active/backup high-availability with a "hot spare" synapse
  pointing at the same DB master, as well as enabling DB replication in
  synapse itself.

For information on how to install and use PostgreSQL, please see
`docs/postgres.md <docs/postgres.md>`_.

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

For information on configuring one, see `<docs/reverse_proxy.md>`_.

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

Then update the ``users`` table in the database::

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
    python -m pip install --no-use-pep517 -e ".[all]"

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

Troubleshooting
===============

Need help? Join our community support room on Matrix:
`#synapse:matrix.org <https://matrix.to/#/#synapse:matrix.org>`_

Running out of File Handles
---------------------------

If synapse runs out of file handles, it typically fails badly - live-locking
at 100% CPU, and/or failing to accept new TCP connections (blocking the
connecting client).  Matrix currently can legitimately use a lot of file handles,
thanks to busy rooms like #matrix:matrix.org containing hundreds of participating
servers.  The first time a server talks in a room it will try to connect
simultaneously to all participating servers, which could exhaust the available
file descriptors between DNS queries & HTTPS sockets, especially if DNS is slow
to respond. (We need to improve the routing algorithm used to be better than
full mesh, but as of March 2019 this hasn't happened yet).

If you hit this failure mode, we recommend increasing the maximum number of
open file handles to be at least 4096 (assuming a default of 1024 or 256).
This is typically done by editing ``/etc/security/limits.conf``

Separately, Synapse may leak file handles if inbound HTTP requests get stuck
during processing - e.g. blocked behind a lock or talking to a remote server etc.
This is best diagnosed by matching up the 'Received request' and 'Processed request'
log lines and looking for any 'Processed request' lines which take more than
a few seconds to execute. Please let us know at #synapse:matrix.org if
you see this failure mode so we can help debug it, however.

Help!! Synapse is slow and eats all my RAM/CPU!
-----------------------------------------------

First, ensure you are running the latest version of Synapse, using Python 3
with a PostgreSQL database.

Synapse's architecture is quite RAM hungry currently - we deliberately
cache a lot of recent room data and metadata in RAM in order to speed up
common requests. We'll improve this in the future, but for now the easiest
way to either reduce the RAM usage (at the risk of slowing things down)
is to set the almost-undocumented ``SYNAPSE_CACHE_FACTOR`` environment
variable. The default is 0.5, which can be decreased to reduce RAM usage
in memory constrained enviroments, or increased if performance starts to
degrade.

However, degraded performance due to a low cache factor, common on
machines with slow disks, often leads to explosions in memory use due
backlogged requests. In this case, reducing the cache factor will make
things worse. Instead, try increasing it drastically. 2.0 is a good
starting value.

Using `libjemalloc <http://jemalloc.net/>`_ can also yield a significant
improvement in overall memory use, and especially in terms of giving back
RAM to the OS. To use it, the library must simply be put in the
LD_PRELOAD environment variable when launching Synapse. On Debian, this
can be done by installing the ``libjemalloc1`` package and adding this
line to ``/etc/default/matrix-synapse``::

    LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.1

This can make a significant difference on Python 2.7 - it's unclear how
much of an improvement it provides on Python 3.x.

If you're encountering high CPU use by the Synapse process itself, you
may be affected by a bug with presence tracking that leads to a
massive excess of outgoing federation requests (see `discussion
<https://github.com/matrix-org/synapse/issues/3971>`_). If metrics
indicate that your server is also issuing far more outgoing federation
requests than can be accounted for by your users' activity, this is a
likely cause. The misbehavior can be worked around by setting
``use_presence: false`` in the Synapse config file.

People can't accept room invitations from me
--------------------------------------------

The typical failure mode here is that you send an invitation to someone 
to join a room or direct chat, but when they go to accept it, they get an
error (typically along the lines of "Invalid signature"). They might see
something like the following in their logs::

    2019-09-11 19:32:04,271 - synapse.federation.transport.server - 288 - WARNING - GET-11752 - authenticate_request failed: 401: Invalid signature for server <server> with key ed25519:a_EqML: Unable to verify signature for <server>

This is normally caused by a misconfiguration in your reverse-proxy. See
`<docs/reverse_proxy.md>`_ and double-check that your settings are correct.
