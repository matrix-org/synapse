# Copyright 2017 New Vector Ltd
# Copyright 2019-2021 The Matrix.org Foundation C.I.C
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
import platform
import signal
import socket
import sys
import traceback
import warnings
from typing import TYPE_CHECKING, Awaitable, Callable, Iterable

from cryptography.utils import CryptographyDeprecationWarning
from typing_extensions import NoReturn

import twisted
from twisted.internet import defer, error, reactor
from twisted.logger import LoggingFile, LogLevel
from twisted.protocols.tls import TLSMemoryBIOFactory

import synapse
from synapse.api.constants import MAX_PDU_SIZE
from synapse.app import check_bind_error
from synapse.app.phone_stats_home import start_phone_stats_home
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.events.spamcheck import load_legacy_spam_checkers
from synapse.logging.context import PreserveLoggingContext
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.metrics.jemalloc import setup_jemalloc_stats
from synapse.util.caches.lrucache import setup_expire_lru_cache_entries
from synapse.util.daemonize import daemonize_process
from synapse.util.rlimit import change_resource_limit
from synapse.util.versionstring import get_version_string

if TYPE_CHECKING:
    from synapse.server import HomeServer

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
    """Run the reactor in the main process

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
    """Run the reactor in the main process

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

    def run():
        logger.info("Running")
        setup_jemalloc_stats()
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
    line_length = min(max(len(line) for line in message_lines), 80) + 2
    sys.stderr.write("*" * line_length + "\n")
    for line in message_lines:
        sys.stderr.write(" %s\n" % (line.rstrip(),))
    sys.stderr.write("*" * line_length + "\n")
    sys.exit(1)


def handle_startup_exception(e: Exception) -> NoReturn:
    # Exceptions that occur between setting up the logging and forking or starting
    # the reactor are written to the logs, followed by a summary to stderr.
    logger.exception("Exception during startup")
    quit_with_error(
        f"Error during initialisation:\n   {e}\nThere may be more information in the logs."
    )


def redirect_stdio_to_logs() -> None:
    streams = [("stdout", LogLevel.info), ("stderr", LogLevel.error)]

    for (stream, level) in streams:
        oldStream = getattr(sys, stream)
        loggingFile = LoggingFile(
            logger=twisted.logger.Logger(namespace=stream),
            level=level,
            encoding=getattr(oldStream, "encoding", None),
        )
        setattr(sys, stream, loggingFile)

    print("Redirected stdout/stderr to logs")


def register_start(cb: Callable[..., Awaitable], *args, **kwargs) -> None:
    """Register a callback with the reactor, to be called once it is running

    This can be used to initialise parts of the system which require an asynchronous
    setup.

    Any exception raised by the callback will be printed and logged, and the process
    will exit.
    """

    async def wrapper():
        try:
            await cb(*args, **kwargs)
        except Exception:
            # previously, we used Failure().printTraceback() here, in the hope that
            # would give better tracebacks than traceback.print_exc(). However, that
            # doesn't handle chained exceptions (with a __cause__ or __context__) well,
            # and I *think* the need for Failure() is reduced now that we mostly use
            # async/await.

            # Write the exception to both the logs *and* the unredirected stderr,
            # because people tend to get confused if it only goes to one or the other.
            #
            # One problem with this is that if people are using a logging config that
            # logs to the console (as is common eg under docker), they will get two
            # copies of the exception. We could maybe try to detect that, but it's
            # probably a cost we can bear.
            logger.fatal("Error during startup", exc_info=True)
            print("Error during startup:", file=sys.__stderr__)
            traceback.print_exc(file=sys.__stderr__)

            # it's no use calling sys.exit here, since that just raises a SystemExit
            # exception which is then caught by the reactor, and everything carries
            # on as normal.
            os._exit(1)

    reactor.callWhenRunning(lambda: defer.ensureDeferred(wrapper()))


def listen_metrics(bind_addresses, port):
    """
    Start Prometheus metrics server.
    """
    from synapse.metrics import RegistryProxy, start_http_server

    for host in bind_addresses:
        logger.info("Starting metrics listener on %s:%d", host, port)
        start_http_server(port, addr=host, registry=RegistryProxy)


def listen_manhole(bind_addresses: Iterable[str], port: int, manhole_globals: dict):
    # twisted.conch.manhole 21.1.0 uses "int_from_bytes", which produces a confusing
    # warning. It's fixed by https://github.com/twisted/twisted/pull/1522), so
    # suppress the warning for now.
    warnings.filterwarnings(
        action="ignore",
        category=CryptographyDeprecationWarning,
        message="int_from_bytes is deprecated",
    )

    from synapse.util.manhole import manhole

    listen_tcp(
        bind_addresses,
        port,
        manhole(username="matrix", password="rabbithole", globals=manhole_globals),
    )


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
        return

    hs.config.read_certificate_from_disk()
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


async def start(hs: "HomeServer"):
    """
    Start a Synapse server or worker.

    Should be called once the reactor is running.

    Will start the main HTTP listeners and do some other startup tasks, and then
    notify systemd.

    Args:
        hs: homeserver instance
    """
    # Set up the SIGHUP machinery.
    if hasattr(signal, "SIGHUP"):
        reactor = hs.get_reactor()

        @wrap_as_background_process("sighup")
        def handle_sighup(*args, **kwargs):
            # Tell systemd our state, if we're using it. This will silently fail if
            # we're not using systemd.
            sdnotify(b"RELOADING=1")

            for i, args, kwargs in _sighup_callbacks:
                i(*args, **kwargs)

            sdnotify(b"READY=1")

        # We defer running the sighup handlers until next reactor tick. This
        # is so that we're in a sane state, e.g. flushing the logs may fail
        # if the sighup happens in the middle of writing a log entry.
        def run_sighup(*args, **kwargs):
            # `callFromThread` should be "signal safe" as well as thread
            # safe.
            reactor.callFromThread(handle_sighup, *args, **kwargs)

        signal.signal(signal.SIGHUP, run_sighup)

        register_sighup(refresh_certificate, hs)

    # Load the certificate from disk.
    refresh_certificate(hs)

    # Start the tracer
    synapse.logging.opentracing.init_tracer(hs)  # type: ignore[attr-defined] # noqa

    # Instantiate the modules so they can register their web resources to the module API
    # before we start the listeners.
    module_api = hs.get_module_api()
    for module, config in hs.config.modules.loaded_modules:
        module(config=config, api=module_api)

    load_legacy_spam_checkers(hs)

    # If we've configured an expiry time for caches, start the background job now.
    setup_expire_lru_cache_entries(hs)

    # It is now safe to start your Synapse.
    hs.start_listening()
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
    if platform.python_implementation() == "CPython" and sys.version_info >= (3, 7):
        gc.collect()
        gc.freeze()


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
    """Adds process state hooks to tell systemd what we are up to."""

    # Tell systemd our state, if we're using it. This will silently fail if
    # we're not using systemd.
    sdnotify(b"READY=1\nMAINPID=%i" % (os.getpid(),))

    hs.get_reactor().addSystemEventTrigger(
        "before", "shutdown", sdnotify, b"STOPPING=1"
    )


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


def max_request_body_size(config: HomeServerConfig) -> int:
    """Get a suitable maximum size for incoming HTTP requests"""

    # Other than media uploads, the biggest request we expect to see is a fully-loaded
    # /federation/v1/send request.
    #
    # The main thing in such a request is up to 50 PDUs, and up to 100 EDUs. PDUs are
    # limited to 65536 bytes (possibly slightly more if the sender didn't use canonical
    # json encoding); there is no specced limit to EDUs (see
    # https://github.com/matrix-org/matrix-doc/issues/3121).
    #
    # in short, we somewhat arbitrarily limit requests to 200 * 64K (about 12.5M)
    #
    max_request_size = 200 * MAX_PDU_SIZE

    # if we have a media repo enabled, we may need to allow larger uploads than that
    if config.media.can_load_media_repo:
        max_request_size = max(max_request_size, config.media.max_upload_size)

    return max_request_size
