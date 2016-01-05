.. contents::

Introduction
============

Matrix is an ambitious new ecosystem for open federated Instant Messaging and
VoIP.  The basics you need to know to get up and running are:

- Everything in Matrix happens in a room.  Rooms are distributed and do not
  exist on any single server.  Rooms can be located using convenience aliases
  like ``#matrix:matrix.org`` or ``#test:localhost:8448``.

- Matrix user IDs look like ``@matthew:matrix.org`` (although in the future
  you will normally refer to yourself and others using a 3PID: email
  address, phone number, etc rather than manipulating Matrix user IDs)

The overall architecture is::

      client <----> homeserver <=====================> homeserver <----> client
             https://somewhere.org/_matrix      https://elsewhere.net/_matrix

``#matrix:matrix.org`` is the official support room for Matrix, and can be
accessed by any client from https://matrix.org/blog/try-matrix-now or via IRC
bridge at irc://irc.freenode.net/matrix.

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
development team at matrix.org, written in Python/Twisted for clarity and
simplicity.  It is intended to showcase the concept of Matrix and let folks see
the spec in the context of a codebase and let you run your own homeserver and
generally help bootstrap the ecosystem.

In Matrix, every user runs one or more Matrix clients, which connect through to
a Matrix homeserver which stores all their personal chat history and user
account information - much as a mail client connects through to an IMAP/SMTP
server. Just like email, you can either run your own Matrix homeserver and
control and own your own communications and history or use one hosted by
someone else (e.g. matrix.org) - there is no single point of control or
mandatory service provider in Matrix, unlike WhatsApp, Facebook, Hangouts, etc.

Synapse ships with two basic demo Matrix clients: webclient (a basic group chat
web client demo implemented in AngularJS) and cmdclient (a basic Python
command line utility which lets you easily see what the JSON APIs are up to).

Meanwhile, iOS and Android SDKs and clients are available from:

- https://github.com/matrix-org/matrix-ios-sdk
- https://github.com/matrix-org/matrix-ios-kit
- https://github.com/matrix-org/matrix-ios-console
- https://github.com/matrix-org/matrix-android-sdk

We'd like to invite you to join #matrix:matrix.org (via
https://matrix.org/blog/try-matrix-now), run a homeserver, take a look at the
Matrix spec at https://matrix.org/docs/spec and API docs at
https://matrix.org/docs/api, experiment with the APIs and the demo clients, and
report any bugs via https://matrix.org/jira.

Thanks for using Matrix!

[1] End-to-end encryption is currently in development - see https://matrix.org/git/olm

Synapse Installation
====================

Synapse is the reference python/twisted Matrix homeserver implementation.

System requirements:
- POSIX-compliant system (tested on Linux & OS X)
- Python 2.7
- At least 512 MB RAM.

Synapse is written in python but some of the libraries is uses are written in
C. So before we can install synapse itself we need a working C compiler and the
header files for python C extensions.

Installing prerequisites on Ubuntu or Debian::

    sudo apt-get install build-essential python2.7-dev libffi-dev \
                         python-pip python-setuptools sqlite3 \
                         libssl-dev python-virtualenv libjpeg-dev

Installing prerequisites on ArchLinux::

    sudo pacman -S base-devel python2 python-pip \
                   python-setuptools python-virtualenv sqlite3

Installing prerequisites on CentOS 7::

    sudo yum install libtiff-devel libjpeg-devel libzip-devel freetype-devel \
                     lcms2-devel libwebp-devel tcl-devel tk-devel \
                     python-virtualenv libffi-devel openssl-devel
    sudo yum groupinstall "Development Tools"


Installing prerequisites on Mac OS X::

    xcode-select --install
    sudo easy_install pip
    sudo pip install virtualenv

To install the synapse homeserver run::

    virtualenv -p python2.7 ~/.synapse
    source ~/.synapse/bin/activate
    pip install --upgrade setuptools
    pip install https://github.com/matrix-org/synapse/tarball/master

This installs synapse, along with the libraries it uses, into a virtual
environment under ``~/.synapse``.  Feel free to pick a different directory
if you prefer.

In case of problems, please see the _Troubleshooting section below.

Alternatively, Silvio Fricke has contributed a Dockerfile to automate the
above in Docker at https://registry.hub.docker.com/u/silviof/docker-matrix/.

Another alternative is to install via apt from http://matrix.org/packages/debian/.
Note that these packages do not include  a client - choose one from
https://matrix.org/blog/try-matrix-now/ (or build your own with 
https://github.com/matrix-org/matrix-js-sdk/). 

Finally, Martin Giess has created an auto-deployment process with vagrant/ansible, 
tested with VirtualBox/AWS/DigitalOcean - see https://github.com/EMnify/matrix-synapse-auto-deploy 
for details.

To set up your homeserver, run (in your virtualenv, as before)::

    cd ~/.synapse
    python -m synapse.app.homeserver \
        --server-name machine.my.domain.name \
        --config-path homeserver.yaml \
        --generate-config \
        --report-stats=[yes|no]

...substituting your host and domain name as appropriate.

This will generate you a config file that you can then customise, but it will
also generate a set of keys for you. These keys will allow your Home Server to
identify itself to other Home Servers, so don't lose or delete them. It would be
wise to back them up somewhere safe. If, for whatever reason, you do need to
change your Home Server's keys, you may find that other Home Servers have the
old key cached. If you update the signing key, you should change the name of the
key in the <server name>.signing.key file (the second word, which by default is
, 'auto') to something different.

By default, registration of new users is disabled. You can either enable
registration in the config by specifying ``enable_registration: true``
(it is then recommended to also set up CAPTCHA - see docs/CAPTCHA_SETUP), or
you can use the command line to register new users::

    $ source ~/.synapse/bin/activate
    $ synctl start # if not already running
    $ register_new_matrix_user -c homeserver.yaml https://localhost:8448
    New user localpart: erikj
    Password:
    Confirm password:
    Success!

For reliable VoIP calls to be routed via this homeserver, you MUST configure
a TURN server.  See docs/turn-howto.rst for details.

Running Synapse
===============

To actually run your new homeserver, pick a working directory for Synapse to
run (e.g. ``~/.synapse``), and::

    cd ~/.synapse
    source ./bin/activate
    synctl start

Using PostgreSQL
================

As of Synapse 0.9, `PostgreSQL <http://www.postgresql.org>`_ is supported as an
alternative to the `SQLite <http://sqlite.org/>`_ database that Synapse has
traditionally used for convenience and simplicity.

The advantages of Postgres include:

* significant performance improvements due to the superior threading and
  caching model, smarter query optimiser
* allowing the DB to be run on separate hardware
* allowing basic active/backup high-availability with a "hot spare" synapse
  pointing at the same DB master, as well as enabling DB replication in
  synapse itself.

The only disadvantage is that the code is relatively new as of April 2015 and
may have a few regressions relative to SQLite.

For information on how to install and use PostgreSQL, please see
`docs/postgres.rst <docs/postgres.rst>`_.

Platform Specific Instructions
==============================

ArchLinux
---------

The quickest way to get up and running with ArchLinux is probably with Ivan
Shapovalov's AUR package from
https://aur.archlinux.org/packages/matrix-synapse/, which should pull in all
the necessary dependencies.

Alternatively, to install using pip a few changes may be needed as ArchLinux
defaults to python 3, but synapse currently assumes python 2.7 by default:

pip may be outdated (6.0.7-1 and needs to be upgraded to 6.0.8-1 )::

    sudo pip2.7 install --upgrade pip

You also may need to explicitly specify python 2.7 again during the install
request::

    pip2.7 install https://github.com/matrix-org/synapse/tarball/master

If you encounter an error with lib bcrypt causing an Wrong ELF Class:
ELFCLASS32 (x64 Systems), you may need to reinstall py-bcrypt to correctly
compile it under the right architecture. (This should not be needed if
installing under virtualenv)::

    sudo pip2.7 uninstall py-bcrypt
    sudo pip2.7 install py-bcrypt

During setup of Synapse you need to call python2.7 directly again::

    cd ~/.synapse
    python2.7 -m synapse.app.homeserver \
      --server-name machine.my.domain.name \
      --config-path homeserver.yaml \
      --generate-config

...substituting your host and domain name as appropriate.

Windows Install
---------------
Synapse can be installed on Cygwin. It requires the following Cygwin packages:

- gcc
- git
- libffi-devel
- openssl (and openssl-devel, python-openssl)
- python
- python-setuptools

The content repository requires additional packages and will be unable to process
uploads without them:

- libjpeg8
- libjpeg8-devel
- zlib

If you choose to install Synapse without these packages, you will need to reinstall
``pillow`` for changes to be applied, e.g. ``pip uninstall pillow`` ``pip install
pillow --user``

Troubleshooting:

- You may need to upgrade ``setuptools`` to get this to work correctly:
  ``pip install setuptools --upgrade``.
- You may encounter errors indicating that ``ffi.h`` is missing, even with
  ``libffi-devel`` installed. If you do, copy the ``.h`` files:
  ``cp /usr/lib/libffi-3.0.13/include/*.h /usr/include``
- You may need to install libsodium from source in order to install PyNacl. If
  you do, you may need to create a symlink to ``libsodium.a`` so ``ld`` can find
  it: ``ln -s /usr/local/lib/libsodium.a /usr/lib/libsodium.a``

Troubleshooting
===============

Troubleshooting Installation
----------------------------

Synapse requires pip 1.7 or later, so if your OS provides too old a version you
may need to manually upgrade it::

    sudo pip install --upgrade pip

Installing may fail with ``mock requires setuptools>=17.1. Aborting installation``.
You can fix this by upgrading setuptools::

    pip install --upgrade setuptools

If pip crashes mid-installation for reason (e.g. lost terminal), pip may
refuse to run until you remove the temporary installation directory it
created. To reset the installation::

    rm -rf /tmp/pip_install_matrix

pip seems to leak *lots* of memory during installation.  For instance, a Linux
host with 512MB of RAM may run out of memory whilst installing Twisted.  If this
happens, you will have to individually install the dependencies which are
failing, e.g.::

    pip install twisted

On OS X, if you encounter clang: error: unknown argument: '-mno-fused-madd' you
will need to export CFLAGS=-Qunused-arguments.

Troubleshooting Running
-----------------------

If synapse fails with ``missing "sodium.h"`` crypto errors, you may need
to manually upgrade PyNaCL, as synapse uses NaCl (http://nacl.cr.yp.to/) for
encryption and digital signatures.
Unfortunately PyNACL currently has a few issues
(https://github.com/pyca/pynacl/issues/53) and
(https://github.com/pyca/pynacl/issues/79) that mean it may not install
correctly, causing all tests to fail with errors about missing "sodium.h". To
fix try re-installing from PyPI or directly from
(https://github.com/pyca/pynacl)::

    # Install from PyPI
    pip install --user --upgrade --force pynacl

    # Install from github
    pip install --user https://github.com/pyca/pynacl/tarball/master

ArchLinux
~~~~~~~~~

If running `$ synctl start` fails with 'returned non-zero exit status 1',
you will need to explicitly call Python2.7 - either running as::

    python2.7 -m synapse.app.homeserver --daemonize -c homeserver.yaml

...or by editing synctl with the correct python executable.

Synapse Development
===================

To check out a synapse for development, clone the git repo into a working
directory of your choice::

    git clone https://github.com/matrix-org/synapse.git
    cd synapse

Synapse has a number of external dependencies, that are easiest
to install using pip and a virtualenv::

    virtualenv env
    source env/bin/activate
    python synapse/python_dependencies.py | xargs -n1 pip install
    pip install setuptools_trial mock

This will run a process of downloading and installing all the needed
dependencies into a virtual env.

Once this is done, you may wish to run Synapse's unit tests, to
check that everything is installed as it should be::

    python setup.py test

This should end with a 'PASSED' result::

    Ran 143 tests in 0.601s

    PASSED (successes=143)


Upgrading an existing Synapse
=============================

The instructions for upgrading synapse are in `UPGRADE.rst`_.
Please check these instructions as upgrading may require extra steps for some
versions of synapse.

.. _UPGRADE.rst: UPGRADE.rst

Setting up Federation
=====================

In order for other homeservers to send messages to your server, it will need to
be publicly visible on the internet, and they will need to know its host name.
You have two choices here, which will influence the form of your Matrix user
IDs:

1) Use the machine's own hostname as available on public DNS in the form of
   its A or AAAA records. This is easier to set up initially, perhaps for
   testing, but lacks the flexibility of SRV.

2) Set up a SRV record for your domain name. This requires you create a SRV
   record in DNS, but gives the flexibility to run the server on your own
   choice of TCP port, on a machine that might not be the same name as the
   domain name.

For the first form, simply pass the required hostname (of the machine) as the
--server-name parameter::

    python -m synapse.app.homeserver \
        --server-name machine.my.domain.name \
        --config-path homeserver.yaml \
        --generate-config
    python -m synapse.app.homeserver --config-path homeserver.yaml

Alternatively, you can run ``synctl start`` to guide you through the process.

For the second form, first create your SRV record and publish it in DNS. This
needs to be named _matrix._tcp.YOURDOMAIN, and point at at least one hostname
and port where the server is running.  (At the current time synapse does not
support clustering multiple servers into a single logical homeserver).  The DNS
record would then look something like::

    $ dig -t srv _matrix._tcp.machine.my.domain.name
    _matrix._tcp    IN      SRV     10 0 8448 machine.my.domain.name.


At this point, you should then run the homeserver with the hostname of this
SRV record, as that is the name other machines will expect it to have::

    python -m synapse.app.homeserver \
        --server-name YOURDOMAIN \
        --config-path homeserver.yaml \
        --generate-config
    python -m synapse.app.homeserver --config-path homeserver.yaml


If you've already generated the config file, you need to edit the "server_name"
in you  ```homeserver.yaml``` file. If you've already started Synapse and a
database has been created, you will have to recreate the database.

You may additionally want to pass one or more "-v" options, in order to
increase the verbosity of logging output; at least for initial testing.

Running a Demo Federation of Synapses
-------------------------------------

If you want to get up and running quickly with a trio of homeservers in a
private federation (``localhost:8080``, ``localhost:8081`` and
``localhost:8082``) which you can then access through the webclient running at
http://localhost:8080. Simply run::

    demo/start.sh

This is mainly useful just for development purposes.

Running The Demo Web Client
===========================

The homeserver runs a web client by default at https://localhost:8448/.

If this is the first time you have used the client from that browser (it uses
HTML5 local storage to remember its config), you will need to log in to your
account. If you don't yet have an account, because you've just started the
homeserver for the first time, then you'll need to register one.


Registering A New Account
-------------------------

Your new user name will be formed partly from the hostname your server is
running as, and partly from a localpart you specify when you create the
account. Your name will take the form of::

    @localpart:my.domain.here
         (pronounced "at localpart on my dot domain dot here")

Specify your desired localpart in the topmost box of the "Register for an
account" form, and click the "Register" button. Hostnames can contain ports if
required due to lack of SRV records (e.g. @matthew:localhost:8448 on an
internal synapse sandbox running on localhost).

If registration fails, you may need to enable it in the homeserver (see
`Synapse Installation`_ above)


Logging In To An Existing Account
---------------------------------

Just enter the ``@localpart:my.domain.here`` Matrix user ID and password into
the form and click the Login button.


Identity Servers
================

The job of authenticating 3PIDs and tracking which 3PIDs are associated with a
given Matrix user is very security-sensitive, as there is obvious risk of spam
if it is too easy to sign up for Matrix accounts or harvest 3PID data.
Meanwhile the job of publishing the end-to-end encryption public keys for
Matrix users is also very security-sensitive for similar reasons.

Therefore the role of managing trusted identity in the Matrix ecosystem is
farmed out to a cluster of known trusted ecosystem partners, who run 'Matrix
Identity Servers' such as ``sydent``, whose role is purely to authenticate and
track 3PID logins and publish end-user public keys.

It's currently early days for identity servers as Matrix is not yet using 3PIDs
as the primary means of identity and E2E encryption is not complete. As such,
we are running a single identity server (https://matrix.org) at the current
time.


Where's the spec?!
==================

The source of the matrix spec lives at https://github.com/matrix-org/matrix-doc.
A recent HTML snapshot of this lives at http://matrix.org/docs/spec


Building Internal API Documentation
===================================

Before building internal API documentation install sphinx and
sphinxcontrib-napoleon::

    pip install sphinx
    pip install sphinxcontrib-napoleon

Building internal API documentation::

    python setup.py build_sphinx

