Installation
============

[TODO(kegan): I also needed libffi-dev, which I don't think is included in build-essential.]

First, the dependencies need to be installed. Start by installing 'python-dev'
and the various tools of the compiler toolchain:

  Installing prerequisites on ubuntu::

    $ sudo apt-get install build-essential python-dev

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


Running The Home Server
=======================

In order for other home servers to send messages to your server, they will need
to know its host name. You have two choices here, which will influence the form
of your user IDs:

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
and port where the server is running. (At the current time we only support a
single server, but we may at some future point support multiple servers, for
backup failover or load-balancing purposes). The DNS record would then look
something like::

    _matrix._tcp    IN      SRV     10 0 8448 machine.my.domain.name.

At this point, you should then run the homeserver with the hostname of this
SRV record, as that is the name other machines will expect it to have::

    $ python synapse/app/homeserver.py --host my.domain.name --port 8448

You may additionally want to pass one or more "-v" options, in order to
increase the verbosity of logging output; at least for initial testing.


Running The Web Client
======================

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
account" form, and click the "Register" button.

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
