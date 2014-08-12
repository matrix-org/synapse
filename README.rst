About
=====

Matrix is an ambitious new ecosystem for open federated Instant Messaging and VoIP[1]_.

Matrix specifies a set of pragmatic RESTful HTTP JSON APIs as an open standard, providing:

    - Creating and managing fully distributed chat rooms with no
      single points of control or failure
    - Eventually-consistent cryptographically secure synchronisation of room 
	  state across a global open network of federated servers and services
    - Sending and receiving extensible messages in a room with (optional)
      end-to-end encryption[2]_
    - Inviting, joining, leaving, kicking, banning room members
    - Managing user accounts (registration, login, logout)
    - Using 3rd Party IDs (3PIDs) such as email addresses, phone numbers,
      Facebook accounts to authenticate, identify and discover users on Matrix.
    - Placing 1:1 VoIP and Video calls (in development)

These APIs are intended to be implemented on a wide range of servers, services
and clients which then form the Matrix ecosystem, and allow developers to build
messaging and VoIP functionality on top of the open Matrix community rather than
using closed or proprietary solutions.  The hope is for Matrix to act as the
building blocks for a new generation of fully open and interoperable messaging
and VoIP apps for the internet.

Synapse is a reference "homeserver" implementation of Matrix from the core
development team at matrix.org, written in Python/Twisted for clarity and
simplicity.  It is intended to showcase the concept of Matrix and let folks see
the spec in the context of a codebase and let you run your own homeserver and
generally help bootstrap the ecosystem.

In Matrix, every user runs one or more Matrix clients, which connect through to
a Matrix homeserver which stores all their personal chat history and user
account information - much as a mail client connects through to an IMAP/SMTP
server. Just like email, you can either run your own Matrix homeserver and
control and own your own communications and history or use one hosted by someone
else (e.g. matrix.org) - there is no single point of control or mandatory
service provider in Matrix, unlike WhatsApp, Facebook, Hangouts, etc.

Synapse ships with two basic demo Matrix clients: webclient (a basic group chat web client demo implemented in AngularJS) and cmdclient (a basic Python commandline utility which lets you easily see what the JSON APIs are up to).

We'd like to invite you to take a look at the Matrix spec, try to run a homeserver, and join the existing Matrix chatrooms already out there, experiment with the APIs and the demo clients, and let us know your thoughts at https://github.com/matrix-org/synapse/issues or at matrix@matrix.org.

Thanks for trying Matrix!

.. [1] VoIP currently in development
.. [2] End-to-end encryption is currently in development


Directory Structure
===================

::

    .
    ├── cmdclient           Basic CLI python Matrix client
    ├── demo                Scripts for running standalone Matrix demos
    ├── docs                All doc, including the draft Matrix API spec
    │   ├── client-server   The client-server Matrix API spec
    │   ├── model           Domain-specific elements of the Matrix API spec
    │   ├── server-server   The server-server model of the Matrix API spec
    │   └── sphinx          The internal API doc of the Synapse homeserver
    ├── experiments         Early experiments of using Synapse's internal APIs
    ├── graph               Visualisation of Matrix's distributed message store 
    ├── synapse             The reference Matrix homeserver implementation
    │   ├── api                 Common building blocks for the APIs
    │   │   ├── events              Definition of state representation Events 
    │   │   └── streams             Definition of streamable Event objects
    │   ├── app                 The __main__ entry point for the homeserver
    │   ├── crypto              The PKI client/server used for secure federation
    │   │   └── resource            PKI helper objects (e.g. keys)
    │   ├── federation          Server-server state replication logic
    │   ├── handlers            The main business logic of the homeserver
    │   ├── http                Wrappers around Twisted's HTTP server & client
    │   ├── rest                Servlet-style RESTful API
    │   ├── storage             Persistence subsystem (currently only sqlite3)
    │   │   └── schema              sqlite persistence schema
    │   └── util                Synapse-specific utilities
    ├── tests               Unit tests for the Synapse homeserver
    └── webclient           Basic AngularJS Matrix web client


Installation
============

First, the dependencies need to be installed.  Start by installing 
'python2.7-dev' and the various tools of the compiler toolchain.

N.B. that python 2.x where x >= 7 is required.

  Installing prerequisites on ubuntu::

    $ sudo apt-get install build-essential python2.7-dev libffi-dev

  Installing prerequisites on Mac OS X::

    $ xcode-select --install

The homeserver has a number of external dependencies, that are easiest
to install by making setup.py do so, in --user mode::

    $ python setup.py develop --user

This will run a process of downloading and installing into your
user's .local/lib directory all of the required dependencies that are
missing.

Once this is done, you may wish to run the homeserver's unit tests, to
check that everything is installed as it should be::

    $ python setup.py test

This should end with a 'PASSED' result::

    Ran 143 tests in 0.601s

    PASSED (successes=143)


Running The Synapse Homeserver
==============================

In order for other homeservers to send messages to your server, it will need to
be publicly visible on the internet, and they will need to know its host name.
You have two choices here, which will influence the form of your matrix user
IDs:

 1) Use the machine's own hostname as available on public DNS in the form of its
    A or AAAA records. This is easier to set up initially, perhaps for testing,
    but lacks the flexibility of SRV.

 2) Set up a SRV record for your domain name. This requires you create a SRV
    record in DNS, but gives the flexibility to run the server on your own
    choice of TCP port, on a machine that might not be the same name as the
    domain name.

For the first form, simply pass the required hostname (of the machine) as the
--host parameter::

    $ python synapse/app/homeserver.py --host machine.my.domain.name

For the second form, first create your SRV record and publish it in DNS. This
needs to be named _matrix._tcp.YOURDOMAIN, and point at at least one hostname
and port where the server is running.  (At the current time synapse does not
support clustering multiple servers into a single logical homeserver).  The DNS
record would then look something like::

    _matrix._tcp    IN      SRV     10 0 8448 machine.my.domain.name.

At this point, you should then run the homeserver with the hostname of this
SRV record, as that is the name other machines will expect it to have::

    $ python synapse/app/homeserver.py --host my.domain.name --port 8448

You may additionally want to pass one or more "-v" options, in order to
increase the verbosity of logging output; at least for initial testing.

For the initial alpha release, the homeserver is not speaking TLS for
either client-server or server-server traffic for ease of debugging. We have
also not spent any time yet getting the homeserver to run behind loadbalancers.


Running The Demo Web Client
===========================

At the present time, the web client is not directly served by the homeserver's
HTTP server. To serve this in a form the web browser can reach, arrange for the
'webclient' sub-directory to be made available by any sort of HTTP server that
can serve static files. For example, python's SimpleHTTPServer will suffice::

    $ cd webclient
    $ python -m SimpleHTTPServer

You can now point your browser at  http://localhost:8000/  to find the client.

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
required due to lack of SRV records (e.g. @matthew:localhost:8080 on an internal
synapse sandbox running on localhost)


Logging In To An Existing Account
---------------------------------

[[TODO(paul): It seems the current web client still requests an access_token -
  I suspect this part will need updating before we can point people at how to
  perform e.g. user+password or 3PID authenticated login]]


Building Documentation
======================

Before building documentation install spinx and sphinxcontrib-napoleon::

    $ pip install sphinx
    $ pip install sphinxcontrib-napoleon

Building documentation::

    $ python setup.py build_sphinx
