#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
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
import sys
from typing import Iterable, Iterator

from twisted.application import service
from twisted.internet import defer, reactor
from twisted.python.failure import Failure
from twisted.web.resource import EncodingResourceWrapper, IResource
from twisted.web.server import GzipEncoderFactory
from twisted.web.static import File

import synapse
import synapse.config.logger
from synapse import events
from synapse.api.urls import (
    FEDERATION_PREFIX,
    LEGACY_MEDIA_PREFIX,
    MEDIA_PREFIX,
    SERVER_KEY_V2_PREFIX,
    STATIC_PREFIX,
    WEB_CLIENT_PREFIX,
)
from synapse.app import _base
from synapse.app._base import listen_ssl, listen_tcp, quit_with_error
from synapse.config._base import ConfigError
from synapse.config.emailconfig import ThreepidBehaviour
from synapse.config.homeserver import HomeServerConfig
from synapse.config.server import ListenerConfig
from synapse.federation.transport.server import TransportLayerServer
from synapse.http.additional_resource import AdditionalResource
from synapse.http.server import (
    OptionsResource,
    RootOptionsRedirectResource,
    RootRedirect,
    StaticResource,
)
from synapse.http.site import SynapseSite
from synapse.logging.context import LoggingContext
from synapse.metrics import METRICS_PREFIX, MetricsResource, RegistryProxy
from synapse.python_dependencies import check_requirements
from synapse.replication.http import REPLICATION_PREFIX, ReplicationRestResource
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory
from synapse.rest import ClientRestResource
from synapse.rest.admin import AdminRestResource
from synapse.rest.health import HealthResource
from synapse.rest.key.v2 import KeyApiV2Resource
from synapse.rest.synapse.client.pick_username import pick_username_resource
from synapse.rest.well_known import WellKnownResource
from synapse.server import HomeServer
from synapse.storage import DataStore
from synapse.storage.engines import IncorrectDatabaseSetup
from synapse.storage.prepare_database import UpgradeDatabaseException
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.manhole import manhole
from synapse.util.module_loader import load_module
from synapse.util.rlimit import change_resource_limit
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.homeserver")


def gz_wrap(r):
    return EncodingResourceWrapper(r, [GzipEncoderFactory()])


class SynapseHomeServer(HomeServer):
    DATASTORE_CLASS = DataStore

    def _listener_http(self, config: HomeServerConfig, listener_config: ListenerConfig):
        port = listener_config.port
        bind_addresses = listener_config.bind_addresses
        tls = listener_config.tls
        site_tag = listener_config.http_options.tag
        if site_tag is None:
            site_tag = str(port)

        # We always include a health resource.
        resources = {"/health": HealthResource()}

        for res in listener_config.http_options.resources:
            for name in res.names:
                if name == "openid" and "federation" in res.names:
                    # Skip loading openid resource if federation is defined
                    # since federation resource will include openid
                    continue
                resources.update(self._configure_named_resource(name, res.compress))

        additional_resources = listener_config.http_options.additional_resources
        logger.debug("Configuring additional resources: %r", additional_resources)
        module_api = self.get_module_api()
        for path, resmodule in additional_resources.items():
            handler_cls, config = load_module(
                resmodule,
                ("listeners", site_tag, "additional_resources", "<%s>" % (path,)),
            )
            handler = handler_cls(config, module_api)
            if IResource.providedBy(handler):
                resource = handler
            elif hasattr(handler, "handle_request"):
                resource = AdditionalResource(self, handler.handle_request)
            else:
                raise ConfigError(
                    "additional_resource %s does not implement a known interface"
                    % (resmodule["module"],)
                )
            resources[path] = resource

        # try to find something useful to redirect '/' to
        if WEB_CLIENT_PREFIX in resources:
            root_resource = RootOptionsRedirectResource(WEB_CLIENT_PREFIX)
        elif STATIC_PREFIX in resources:
            root_resource = RootOptionsRedirectResource(STATIC_PREFIX)
        else:
            root_resource = OptionsResource()

        root_resource = create_resource_tree(resources, root_resource)

        if tls:
            ports = listen_ssl(
                bind_addresses,
                port,
                SynapseSite(
                    "synapse.access.https.%s" % (site_tag,),
                    site_tag,
                    listener_config,
                    root_resource,
                    self.version_string,
                ),
                self.tls_server_context_factory,
                reactor=self.get_reactor(),
            )
            logger.info("Synapse now listening on TCP port %d (TLS)", port)

        else:
            ports = listen_tcp(
                bind_addresses,
                port,
                SynapseSite(
                    "synapse.access.http.%s" % (site_tag,),
                    site_tag,
                    listener_config,
                    root_resource,
                    self.version_string,
                ),
                reactor=self.get_reactor(),
            )
            logger.info("Synapse now listening on TCP port %d", port)

        return ports

    def _configure_named_resource(self, name, compress=False):
        """Build a resource map for a named resource

        Args:
            name (str): named resource: one of "client", "federation", etc
            compress (bool): whether to enable gzip compression for this
                resource

        Returns:
            dict[str, Resource]: map from path to HTTP resource
        """
        resources = {}
        if name == "client":
            client_resource = ClientRestResource(self)
            if compress:
                client_resource = gz_wrap(client_resource)

            resources.update(
                {
                    "/_matrix/client/api/v1": client_resource,
                    "/_matrix/client/r0": client_resource,
                    "/_matrix/client/unstable": client_resource,
                    "/_matrix/client/v2_alpha": client_resource,
                    "/_matrix/client/versions": client_resource,
                    "/.well-known/matrix/client": WellKnownResource(self),
                    "/_synapse/admin": AdminRestResource(self),
                    "/_synapse/client/pick_username": pick_username_resource(self),
                }
            )

            if self.get_config().oidc_enabled:
                from synapse.rest.oidc import OIDCResource

                resources["/_synapse/oidc"] = OIDCResource(self)

            if self.get_config().saml2_enabled:
                from synapse.rest.saml2 import SAML2Resource

                resources["/_matrix/saml2"] = SAML2Resource(self)

            if self.get_config().threepid_behaviour_email == ThreepidBehaviour.LOCAL:
                from synapse.rest.synapse.client.password_reset import (
                    PasswordResetSubmitTokenResource,
                )

                resources[
                    "/_synapse/client/password_reset/email/submit_token"
                ] = PasswordResetSubmitTokenResource(self)

        if name == "consent":
            from synapse.rest.consent.consent_resource import ConsentResource

            consent_resource = ConsentResource(self)
            if compress:
                consent_resource = gz_wrap(consent_resource)
            resources.update({"/_matrix/consent": consent_resource})

        if name == "federation":
            resources.update({FEDERATION_PREFIX: TransportLayerServer(self)})

        if name == "openid":
            resources.update(
                {
                    FEDERATION_PREFIX: TransportLayerServer(
                        self, servlet_groups=["openid"]
                    )
                }
            )

        if name in ["static", "client"]:
            resources.update(
                {
                    STATIC_PREFIX: StaticResource(
                        os.path.join(os.path.dirname(synapse.__file__), "static")
                    )
                }
            )

        if name in ["media", "federation", "client"]:
            if self.get_config().enable_media_repo:
                media_repo = self.get_media_repository_resource()
                resources.update(
                    {MEDIA_PREFIX: media_repo, LEGACY_MEDIA_PREFIX: media_repo}
                )
            elif name == "media":
                raise ConfigError(
                    "'media' resource conflicts with enable_media_repo=False"
                )

        if name in ["keys", "federation"]:
            resources[SERVER_KEY_V2_PREFIX] = KeyApiV2Resource(self)

        if name == "webclient":
            webclient_loc = self.get_config().web_client_location

            if webclient_loc is None:
                logger.warning(
                    "Not enabling webclient resource, as web_client_location is unset."
                )
            elif webclient_loc.startswith("http://") or webclient_loc.startswith(
                "https://"
            ):
                resources[WEB_CLIENT_PREFIX] = RootRedirect(webclient_loc)
            else:
                logger.warning(
                    "Running webclient on the same domain is not recommended: "
                    "https://github.com/matrix-org/synapse#security-note - "
                    "after you move webclient to different host you can set "
                    "web_client_location to its full URL to enable redirection."
                )
                # GZip is disabled here due to
                # https://twistedmatrix.com/trac/ticket/7678
                resources[WEB_CLIENT_PREFIX] = File(webclient_loc)

        if name == "metrics" and self.get_config().enable_metrics:
            resources[METRICS_PREFIX] = MetricsResource(RegistryProxy)

        if name == "replication":
            resources[REPLICATION_PREFIX] = ReplicationRestResource(self)

        return resources

    def start_listening(self, listeners: Iterable[ListenerConfig]):
        config = self.get_config()

        if config.redis_enabled:
            # If redis is enabled we connect via the replication command handler
            # in the same way as the workers (since we're effectively a client
            # rather than a server).
            self.get_tcp_replication().start_replication(self)

        for listener in listeners:
            if listener.type == "http":
                self._listening_services.extend(self._listener_http(config, listener))
            elif listener.type == "manhole":
                listen_tcp(
                    listener.bind_addresses,
                    listener.port,
                    manhole(
                        username="matrix", password="rabbithole", globals={"hs": self}
                    ),
                )
            elif listener.type == "replication":
                services = listen_tcp(
                    listener.bind_addresses,
                    listener.port,
                    ReplicationStreamProtocolFactory(self),
                )
                for s in services:
                    reactor.addSystemEventTrigger("before", "shutdown", s.stopListening)
            elif listener.type == "metrics":
                if not self.get_config().enable_metrics:
                    logger.warning(
                        (
                            "Metrics listener configured, but "
                            "enable_metrics is not True!"
                        )
                    )
                else:
                    _base.listen_metrics(listener.bind_addresses, listener.port)
            else:
                # this shouldn't happen, as the listener type should have been checked
                # during parsing
                logger.warning("Unrecognized listener type: %s", listener.type)


def setup(config_options):
    """
    Args:
        config_options_options: The options passed to Synapse. Usually
            `sys.argv[1:]`.

    Returns:
        HomeServer
    """
    try:
        config = HomeServerConfig.load_or_generate_config(
            "Synapse Homeserver", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n")
        for f in format_config_error(e):
            sys.stderr.write(f)
        sys.stderr.write("\n")
        sys.exit(1)

    if not config:
        # If a config isn't returned, and an exception isn't raised, we're just
        # generating config files and shouldn't try to continue.
        sys.exit(0)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    hs = SynapseHomeServer(
        config.server_name,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
    )

    synapse.config.logger.setup_logging(hs, config, use_worker_options=False)

    logger.info("Setting up server")

    try:
        hs.setup()
    except IncorrectDatabaseSetup as e:
        quit_with_error(str(e))
    except UpgradeDatabaseException as e:
        quit_with_error("Failed to upgrade database: %s" % (e,))

    async def do_acme() -> bool:
        """
        Reprovision an ACME certificate, if it's required.

        Returns:
            Whether the cert has been updated.
        """
        acme = hs.get_acme_handler()

        # Check how long the certificate is active for.
        cert_days_remaining = hs.config.is_disk_cert_valid(allow_self_signed=False)

        # We want to reprovision if cert_days_remaining is None (meaning no
        # certificate exists), or the days remaining number it returns
        # is less than our re-registration threshold.
        provision = False

        if (
            cert_days_remaining is None
            or cert_days_remaining < hs.config.acme_reprovision_threshold
        ):
            provision = True

        if provision:
            await acme.provision_certificate()

        return provision

    async def reprovision_acme():
        """
        Provision a certificate from ACME, if required, and reload the TLS
        certificate if it's renewed.
        """
        reprovisioned = await do_acme()
        if reprovisioned:
            _base.refresh_certificate(hs)

    async def start():
        try:
            # Run the ACME provisioning code, if it's enabled.
            if hs.config.acme_enabled:
                acme = hs.get_acme_handler()
                # Start up the webservices which we will respond to ACME
                # challenges with, and then provision.
                await acme.start_listening()
                await do_acme()

                # Check if it needs to be reprovisioned every day.
                hs.get_clock().looping_call(reprovision_acme, 24 * 60 * 60 * 1000)

            # Load the OIDC provider metadatas, if OIDC is enabled.
            if hs.config.oidc_enabled:
                oidc = hs.get_oidc_handler()
                # Loading the provider metadata also ensures the provider config is valid.
                await oidc.load_metadata()
                await oidc.load_jwks()

            _base.start(hs, config.listeners)

            hs.get_datastore().db_pool.updates.start_doing_background_updates()
        except Exception:
            # Print the exception and bail out.
            print("Error during startup:", file=sys.stderr)

            # this gives better tracebacks than traceback.print_exc()
            Failure().printTraceback(file=sys.stderr)

            if reactor.running:
                reactor.stop()
            sys.exit(1)

    reactor.callWhenRunning(lambda: defer.ensureDeferred(start()))

    return hs


def format_config_error(e: ConfigError) -> Iterator[str]:
    """
    Formats a config error neatly

    The idea is to format the immediate error, plus the "causes" of those errors,
    hopefully in a way that makes sense to the user. For example:

        Error in configuration at 'oidc_config.user_mapping_provider.config.display_name_template':
          Failed to parse config for module 'JinjaOidcMappingProvider':
            invalid jinja template:
              unexpected end of template, expected 'end of print statement'.

    Args:
        e: the error to be formatted

    Returns: An iterator which yields string fragments to be formatted
    """
    yield "Error in configuration"

    if e.path:
        yield " at '%s'" % (".".join(e.path),)

    yield ":\n  %s" % (e.msg,)

    e = e.__cause__
    indent = 1
    while e:
        indent += 1
        yield ":\n%s%s" % ("  " * indent, str(e))
        e = e.__cause__


class SynapseService(service.Service):
    """
    A twisted Service class that will start synapse. Used to run synapse
    via twistd and a .tac.
    """

    def __init__(self, config):
        self.config = config

    def startService(self):
        hs = setup(self.config)
        change_resource_limit(hs.config.soft_file_limit)
        if hs.config.gc_thresholds:
            gc.set_threshold(*hs.config.gc_thresholds)

    def stopService(self):
        return self._port.stopListening()


def run(hs):
    PROFILE_SYNAPSE = False
    if PROFILE_SYNAPSE:

        def profile(func):
            from cProfile import Profile
            from threading import current_thread

            def profiled(*args, **kargs):
                profile = Profile()
                profile.enable()
                func(*args, **kargs)
                profile.disable()
                ident = current_thread().ident
                profile.dump_stats(
                    "/tmp/%s.%s.%i.pstat" % (hs.hostname, func.__name__, ident)
                )

            return profiled

        from twisted.python.threadpool import ThreadPool

        ThreadPool._worker = profile(ThreadPool._worker)
        reactor.run = profile(reactor.run)

    _base.start_reactor(
        "synapse-homeserver",
        soft_file_limit=hs.config.soft_file_limit,
        gc_thresholds=hs.config.gc_thresholds,
        pid_file=hs.config.pid_file,
        daemonize=hs.config.daemonize,
        print_pidfile=hs.config.print_pidfile,
        logger=logger,
    )


def main():
    with LoggingContext("main"):
        # check base requirements
        check_requirements()
        hs = setup(sys.argv[1:])
        run(hs)


if __name__ == "__main__":
    main()
