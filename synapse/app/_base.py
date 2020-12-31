# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import gc
import logging
import os
import signal
import socket
import sys
import traceback
from typing import Iterable

from typing_extensions import NoReturn

from twisted.internet import defer, error, reactor
from twisted.protocols.tls import TLSMemoryBIOFactory

import synapse
from synapse.app import check_bind_error
from synapse.app.phone_stats_home import start_phone_stats_home
from synapse.config.server import ListenerConfig
from synapse.crypto import context_factory
from synapse.logging.context import PreserveLoggingContext
from synapse.util.async_helpers import Linearizer
from synapse.util.daemonize import daemonize_process
from synapse.util.rlimit import change_resource_limit
from synapse.util.versionstring import get_version_string

logger = logging.getLogger(__name__)

# list of tuples of function, args list, kwargs dict
_sighup_callbacks = []


def register_sighup(func, *args, **kwargs):
    """
    Register a function to be called when a SIGHUP occurs.

    Args:
        func (function): Function to be called when sent a SIGHUP signal.
        *args, **kwargs: args and kwargs to be passed to the target function.
    """
    _sighup_callbacks.append((func, args, kwargs))


def start_worker_reactor(appname, config, run_command=reactor.run):
    """ Run the reactor in the main process

    Daemonizes if necessary, and then configures some resources, before starting
    the reactor. Pulls configuration from the 'worker' settings in 'config'.

    Args:
        appname (str): application name which will be sent to syslog
        config (synapse.config.Config): config object
        run_command (Callable[]): callable that actually runs the reactor
    """

    logger = logging.getLogger(config.worker_app)

    start_reactor(
        appname,
        soft_file_limit=config.soft_file_limit,
        gc_thresholds=config.gc_thresholds,
        pid_file=config.worker_pid_file,
        daemonize=config.worker_daemonize,
        print_pidfile=config.print_pidfile,
        logger=logger,
        run_command=run_command,
    )


def start_reactor(
    appname,
    soft_file_limit,
    gc_thresholds,
    pid_file,
    daemonize,
    print_pidfile,
    logger,
    run_command=reactor.run,
):
    """ Run the reactor in the main process

    Daemonizes if necessary, and then configures some resources, before starting
    the reactor

    Args:
        appname (str): application name which will be sent to syslog
        soft_file_limit (int):
        gc_thresholds:
        pid_file (str): name of pid file to write to if daemonize is True
        daemonize (bool): true to run the reactor in a background process
        print_pidfile (bool): whether to print the pid file, if daemonize is True
        logger (logging.Logger): logger instance to pass to Daemonize
        run_command (Callable[]): callable that actually runs the reactor
    """

    install_dns_limiter(reactor)

    def run():
        logger.info("Running")
        change_resource_limit(soft_file_limit)
        if gc_thresholds:
            gc.set_threshold(*gc_thresholds)
        run_command()

    # make sure that we run the reactor with the sentinel log context,
    # otherwise other PreserveLoggingContext instances will get confused
    # and complain when they see the logcontext arbitrarily swapping
    # between the sentinel and `run` logcontexts.
    #
    # We also need to drop the logcontext before forking if we're daemonizing,
    # otherwise the cputime metrics get confused about the per-thread resource usage
    # appearing to go backwards.
    with PreserveLoggingContext():
        if daemonize:
            if print_pidfile:
                print(pid_file)

            daemonize_process(pid_file, logger)
        run()


def quit_with_error(error_string: str) -> NoReturn:
    message_lines = error_string.split("\n")
    line_length = max(len(line) for line in message_lines if len(line) < 80) + 2
    sys.stderr.write("*" * line_length + "\n")
    for line in message_lines:
        sys.stderr.write(" %s\n" % (line.rstrip(),))
    sys.stderr.write("*" * line_length + "\n")
    sys.exit(1)


def listen_metrics(bind_addresses, port):
    """
    Start Prometheus metrics server.
    """
    from synapse.metrics import RegistryProxy, start_http_server

    for host in bind_addresses:
        logger.info("Starting metrics listener on %s:%d", host, port)
        start_http_server(port, addr=host, registry=RegistryProxy)


def listen_tcp(bind_addresses, port, factory, reactor=reactor, backlog=50):
    """
    Create a TCP socket for a port and several addresses

    Returns:
        list[twisted.internet.tcp.Port]: listening for TCP connections
    """
    r = []
    for address in bind_addresses:
        try:
            r.append(reactor.listenTCP(port, factory, backlog, address))
        except error.CannotListenError as e:
            check_bind_error(e, address, bind_addresses)

    return r


def listen_ssl(
    bind_addresses, port, factory, context_factory, reactor=reactor, backlog=50
):
    """
    Create an TLS-over-TCP socket for a port and several addresses

    Returns:
        list of twisted.internet.tcp.Port listening for TLS connections
    """
    r = []
    for address in bind_addresses:
        try:
            r.append(
                reactor.listenSSL(port, factory, context_factory, backlog, address)
            )
        except error.CannotListenError as e:
            check_bind_error(e, address, bind_addresses)

    return r


def refresh_certificate(hs):
    """
    Refresh the TLS certificates that Synapse is using by re-reading them from
    disk and updating the TLS context factories to use them.
    """

    if not hs.config.has_tls_listener():
        # attempt to reload the certs for the good of the tls_fingerprints
        hs.config.read_certificate_from_disk(require_cert_and_key=False)
        return

    hs.config.read_certificate_from_disk(require_cert_and_key=True)
    hs.tls_server_context_factory = context_factory.ServerContextFactory(hs.config)

    if hs._listening_services:
        logger.info("Updating context factories...")
        for i in hs._listening_services:
            # When you listenSSL, it doesn't make an SSL port but a TCP one with
            # a TLS wrapping factory around the factory you actually want to get
            # requests. This factory attribute is public but missing from
            # Twisted's documentation.
            if isinstance(i.factory, TLSMemoryBIOFactory):
                addr = i.getHost()
                logger.info(
                    "Replacing TLS context factory on [%s]:%i", addr.host, addr.port
                )
                # We want to replace TLS factories with a new one, with the new
                # TLS configuration. We do this by reaching in and pulling out
                # the wrappedFactory, and then re-wrapping it.
                i.factory = TLSMemoryBIOFactory(
                    hs.tls_server_context_factory, False, i.factory.wrappedFactory
                )
        logger.info("Context factories updated.")


def start(hs: "synapse.server.HomeServer", listeners: Iterable[ListenerConfig]):
    """
    Start a Synapse server or worker.

    Should be called once the reactor is running and (if we're using ACME) the
    TLS certificates are in place.

    Will start the main HTTP listeners and do some other startup tasks, and then
    notify systemd.

    Args:
        hs: homeserver instance
        listeners: Listener configuration ('listeners' in homeserver.yaml)
    """
    try:
        # Set up the SIGHUP machinery.
        if hasattr(signal, "SIGHUP"):

            def handle_sighup(*args, **kwargs):
                # Tell systemd our state, if we're using it. This will silently fail if
                # we're not using systemd.
                sdnotify(b"RELOADING=1")

                for i, args, kwargs in _sighup_callbacks:
                    i(*args, **kwargs)

                sdnotify(b"READY=1")

            signal.signal(signal.SIGHUP, handle_sighup)

            register_sighup(refresh_certificate, hs)

        # Load the certificate from disk.
        refresh_certificate(hs)

        # Start the tracer
        synapse.logging.opentracing.init_tracer(  # type: ignore[attr-defined] # noqa
            hs
        )

        # It is now safe to start your Synapse.
        hs.start_listening(listeners)
        hs.get_datastore().db_pool.start_profiling()
        hs.get_pusherpool().start()

        # Log when we start the shut down process.
        hs.get_reactor().addSystemEventTrigger(
            "before", "shutdown", logger.info, "Shutting down..."
        )

        setup_sentry(hs)
        setup_sdnotify(hs)

        # If background tasks are running on the main process, start collecting the
        # phone home stats.
        if hs.config.run_background_tasks:
            start_phone_stats_home(hs)

        # We now freeze all allocated objects in the hopes that (almost)
        # everything currently allocated are things that will be used for the
        # rest of time. Doing so means less work each GC (hopefully).
        #
        # This only works on Python 3.7
        if sys.version_info >= (3, 7):
            gc.collect()
            gc.freeze()
    except Exception:
        traceback.print_exc(file=sys.stderr)
        reactor = hs.get_reactor()
        if reactor.running:
            reactor.stop()
        sys.exit(1)


def setup_sentry(hs):
    """Enable sentry integration, if enabled in configuration

    Args:
        hs (synapse.server.HomeServer)
    """

    if not hs.config.sentry_enabled:
        return

    import sentry_sdk

    sentry_sdk.init(dsn=hs.config.sentry_dsn, release=get_version_string(synapse))

    # We set some default tags that give some context to this instance
    with sentry_sdk.configure_scope() as scope:
        scope.set_tag("matrix_server_name", hs.config.server_name)

        app = hs.config.worker_app if hs.config.worker_app else "synapse.app.homeserver"
        name = hs.get_instance_name()
        scope.set_tag("worker_app", app)
        scope.set_tag("worker_name", name)


def setup_sdnotify(hs):
    """Adds process state hooks to tell systemd what we are up to.
    """

    # Tell systemd our state, if we're using it. This will silently fail if
    # we're not using systemd.
    sdnotify(b"READY=1\nMAINPID=%i" % (os.getpid(),))

    hs.get_reactor().addSystemEventTrigger(
        "before", "shutdown", sdnotify, b"STOPPING=1"
    )


def install_dns_limiter(reactor, max_dns_requests_in_flight=100):
    """Replaces the resolver with one that limits the number of in flight DNS
    requests.

    This is to workaround https://twistedmatrix.com/trac/ticket/9620, where we
    can run out of file descriptors and infinite loop if we attempt to do too
    many DNS queries at once

    XXX: I'm confused by this. reactor.nameResolver does not use twisted.names unless
    you explicitly install twisted.names as the resolver; rather it uses a GAIResolver
    backed by the reactor's default threadpool (which is limited to 10 threads). So
    (a) I don't understand why twisted ticket 9620 is relevant, and (b) I don't
    understand why we would run out of FDs if we did too many lookups at once.
    -- richvdh 2020/08/29
    """
    new_resolver = _LimitedHostnameResolver(
        reactor.nameResolver, max_dns_requests_in_flight
    )

    reactor.installNameResolver(new_resolver)


class _LimitedHostnameResolver:
    """Wraps a IHostnameResolver, limiting the number of in-flight DNS lookups.
    """

    def __init__(self, resolver, max_dns_requests_in_flight):
        self._resolver = resolver
        self._limiter = Linearizer(
            name="dns_client_limiter", max_count=max_dns_requests_in_flight
        )

    def resolveHostName(
        self,
        resolutionReceiver,
        hostName,
        portNumber=0,
        addressTypes=None,
        transportSemantics="TCP",
    ):
        # We need this function to return `resolutionReceiver` so we do all the
        # actual logic involving deferreds in a separate function.

        # even though this is happening within the depths of twisted, we need to drop
        # our logcontext before starting _resolve, otherwise: (a) _resolve will drop
        # the logcontext if it returns an incomplete deferred; (b) _resolve will
        # call the resolutionReceiver *with* a logcontext, which it won't be expecting.
        with PreserveLoggingContext():
            self._resolve(
                resolutionReceiver,
                hostName,
                portNumber,
                addressTypes,
                transportSemantics,
            )

        return resolutionReceiver

    @defer.inlineCallbacks
    def _resolve(
        self,
        resolutionReceiver,
        hostName,
        portNumber=0,
        addressTypes=None,
        transportSemantics="TCP",
    ):

        with (yield self._limiter.queue(())):
            # resolveHostName doesn't return a Deferred, so we need to hook into
            # the receiver interface to get told when resolution has finished.

            deferred = defer.Deferred()
            receiver = _DeferredResolutionReceiver(resolutionReceiver, deferred)

            self._resolver.resolveHostName(
                receiver, hostName, portNumber, addressTypes, transportSemantics
            )

            yield deferred


class _DeferredResolutionReceiver:
    """Wraps a IResolutionReceiver and simply resolves the given deferred when
    resolution is complete
    """

    def __init__(self, receiver, deferred):
        self._receiver = receiver
        self._deferred = deferred

    def resolutionBegan(self, resolutionInProgress):
        self._receiver.resolutionBegan(resolutionInProgress)

    def addressResolved(self, address):
        self._receiver.addressResolved(address)

    def resolutionComplete(self):
        self._deferred.callback(())
        self._receiver.resolutionComplete()


sdnotify_sockaddr = os.getenv("NOTIFY_SOCKET")


def sdnotify(state):
    """
    Send a notification to systemd, if the NOTIFY_SOCKET env var is set.

    This function is based on the sdnotify python package, but since it's only a few
    lines of code, it's easier to duplicate it here than to add a dependency on a
    package which many OSes don't include as a matter of principle.

    Args:
        state (bytes): notification to send
    """
    if not isinstance(state, bytes):
        raise TypeError("sdnotify should be called with a bytes")
    if not sdnotify_sockaddr:
        return
    addr = sdnotify_sockaddr
    if addr[0] == "@":
        addr = "\0" + addr[1:]

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(addr)
            sock.sendall(state)
    except Exception as e:
        # this is a bit surprising, since we don't expect to have a NOTIFY_SOCKET
        # unless systemd is expecting us to notify it.
        logger.warning("Unable to send notification to systemd: %s", e)
