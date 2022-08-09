=========================================================================
Synapse |support| |development| |documentation| |license| |pypi| |python|
=========================================================================

Synapse is an open-source `Matrix <https://matrix.org/>`_ homeserver written and
maintained by the Matrix.org Foundation. We began rapid development began in 2014,
reaching v1.0.0 in 2019. Development on Synapse and the Matrix protocol itself continues
in earnest today.

Briefly, Matrix is an open standard for communications on the internet, supporting
federation, encryption and VoIP. Matrix.org has more to say about the `goals of the
Matrix project <https://matrix.org/docs/guides/introduction>`_, and the `formal specification
<https://spec.matrix.org/>`_ describes the technical details.

.. contents::


Support
=======

For support installing or managing Synapse, please join |room|_ (from a matrix.org
account if necessary) and ask questions there. We do not use GitHub issues for
support requests, only for bug reports and feature requests.

Synapse's documentation is `nicely rendered on GitHub Pages <https://matrix-org.github.io/synapse>`_,
with its source available in |docs|_.

.. |room| replace:: ``#synapse:matrix.org``
.. _room: https://matrix.to/#/#synapse:matrix.org

.. |docs| replace:: ``docs``
.. _docs: docs

Synapse Installation
====================

.. _federation:

* For details on how to install Synapse, see
  `Installation Instructions <https://matrix-org.github.io/synapse/latest/setup/installation.html>`_.
* For specific details on how to configure Synapse for federation see `docs/federate.md <docs/federate.md>`_


Connecting to Synapse from a client
===================================

The easiest way to try out your new Synapse installation is by connecting to it
from a web client.

Unless you are running a test instance of Synapse on your local machine, in
general, you will need to enable TLS support before you can successfully
connect from a client: see
`TLS certificates <https://matrix-org.github.io/synapse/latest/setup/installation.html#tls-certificates>`_.

An easy way to get started is to login or register via Element at
https://app.element.io/#/login or https://app.element.io/#/register respectively.
You will need to change the server you are logging into from ``matrix.org``
and instead specify a Homeserver URL of ``https://<server_name>:8448``
(or just ``https://<server_name>`` if you are using a reverse proxy).
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
user via a Matrix client.

Your new user name will be formed partly from the ``server_name``, and partly
from a localpart you specify when you create the account. Your name will take
the form of::

    @localpart:my.domain.name

(pronounced "at localpart on my dot domain dot name").

As when logging in, you will need to specify a "Custom server".  Specify your
desired ``localpart`` in the 'User name' box.

Security note
=============

Matrix serves raw, user-supplied data in some APIs -- specifically the `content
repository endpoints`_.

.. _content repository endpoints: https://matrix.org/docs/spec/client_server/latest.html#get-matrix-media-r0-download-servername-mediaid

Whilst we make a reasonable effort to mitigate against XSS attacks (for
instance, by using `CSP`_), a Matrix homeserver should not be hosted on a
domain hosting other web applications. This especially applies to sharing
the domain with Matrix web clients and other sensitive applications like
webmail. See
https://developer.github.com/changes/2014-04-25-user-content-security for more
information.

.. _CSP: https://github.com/matrix-org/synapse/pull/1021

Ideally, the homeserver should not simply be on a different subdomain, but on
a completely different `registered domain`_ (also known as top-level site or
eTLD+1). This is because `some attacks`_ are still possible as long as the two
applications share the same registered domain.

.. _registered domain: https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-03#section-2.3

.. _some attacks: https://en.wikipedia.org/wiki/Session_fixation#Attacks_using_cross-subdomain_cookie

To illustrate this with an example, if your Element Web or other sensitive web
application is hosted on ``A.example1.com``, you should ideally host Synapse on
``example2.com``. Some amount of protection is offered by hosting on
``B.example1.com`` instead, so this is also acceptable in some scenarios.
However, you should *not* host your Synapse on ``A.example1.com``.

Note that all of the above refers exclusively to the domain used in Synapse's
``public_baseurl`` setting. In particular, it has no bearing on the domain
mentioned in MXIDs hosted on that server.

Following this advice ensures that even if an XSS is found in Synapse, the
impact to other applications will be minimal.


Upgrading an existing Synapse
=============================

The instructions for upgrading Synapse are in `the upgrade notes`_.
Please check these instructions as upgrading may require extra steps for some
versions of Synapse.

.. _the upgrade notes: https://matrix-org.github.io/synapse/develop/upgrade.html

.. _reverse-proxy:

Using a reverse proxy with Synapse
==================================

It is recommended to put a reverse proxy such as
`nginx <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>`_,
`Apache <https://httpd.apache.org/docs/current/mod/mod_proxy_http.html>`_,
`Caddy <https://caddyserver.com/docs/quick-starts/reverse-proxy>`_,
`HAProxy <https://www.haproxy.org/>`_ or
`relayd <https://man.openbsd.org/relayd.8>`_ in front of Synapse. One advantage of
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


Development
===========

We welcome contributions to Synapse from the community!
The best place to get started is our
`guide for contributors <https://matrix-org.github.io/synapse/latest/development/contributing_guide.html>`_.
This is part of our larger `documentation <https://matrix-org.github.io/synapse/latest>`_, which includes

information for Synapse developers as well as Synapse administrators.
Developers might be particularly interested in:

* `Synapse's database schema <https://matrix-org.github.io/synapse/latest/development/database_schema.html>`_,
* `notes on Synapse's implementation details <https://matrix-org.github.io/synapse/latest/development/internal_documentation/index.html>`_, and
* `how we use git <https://matrix-org.github.io/synapse/latest/development/git.html>`_.

Alongside all that, join our developer community on Matrix:
`#synapse-dev:matrix.org <https://matrix.to/#/#synapse-dev:matrix.org>`_, featuring real humans!


Platform dependencies
=====================

Synapse uses a number of platform dependencies such as Python and PostgreSQL,
and aims to follow supported upstream versions. See the
`<docs/deprecation_policy.md>`_ document for more details.


Troubleshooting
===============

The `Admin FAQ <https://matrix-org.github.io/synapse/latest/development/contributing_guide.html>`_
includes tips on dealing with some common problems.

If that doesn't help, join our community support room on Matrix:
`#synapse:matrix.org <https://matrix.to/#/#synapse:matrix.org>`_.


.. |support| image:: https://img.shields.io/matrix/synapse:matrix.org?label=support&logo=matrix
  :alt: (get support on #synapse:matrix.org)
  :target: https://matrix.to/#/#synapse:matrix.org

.. |development| image:: https://img.shields.io/matrix/synapse-dev:matrix.org?label=development&logo=matrix
  :alt: (discuss development on #synapse-dev:matrix.org)
  :target: https://matrix.to/#/#synapse-dev:matrix.org

.. |documentation| image:: https://img.shields.io/badge/documentation-%E2%9C%93-success
  :alt: (Rendered documentation on GitHub Pages)
  :target: https://matrix-org.github.io/synapse/latest/

.. |license| image:: https://img.shields.io/github/license/matrix-org/synapse
  :alt: (check license in LICENSE file)
  :target: LICENSE

.. |pypi| image:: https://img.shields.io/pypi/v/matrix-synapse
  :alt: (latest version released on PyPi)
  :target: https://pypi.org/project/matrix-synapse

.. |python| image:: https://img.shields.io/pypi/pyversions/matrix-synapse
  :alt: (supported python versions)
  :target: https://pypi.org/project/matrix-synapse
