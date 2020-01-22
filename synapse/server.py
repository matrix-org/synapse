# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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


# This file provides some classes for setting up (partially-populated)
# homeservers; either as a full homeserver as a real application, or a small
# partial one for unit test mocking.

# Imports required for the default HomeServer() implementation
import abc
import logging
import os
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, cast

from twisted.internet import tcp
from twisted.mail.smtp import sendmail
from twisted.web.client import BrowserLikePolicyForHTTPS
from twisted.web.iweb import IPolicyForHTTPS

import synapse
from synapse.api.auth import Auth
from synapse.api.filtering import Filtering
from synapse.api.ratelimiting import Ratelimiter
from synapse.appservice.api import ApplicationServiceApi
from synapse.appservice.scheduler import ApplicationServiceScheduler
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.crypto.keyring import Keyring
from synapse.events.builder import EventBuilderFactory
from synapse.events.spamcheck import SpamChecker
from synapse.events.third_party_rules import ThirdPartyEventRules
from synapse.events.utils import EventClientSerializer
from synapse.federation.federation_client import FederationClient
from synapse.federation.federation_server import (
    FederationHandlerRegistry,
    FederationServer,
    ReplicationFederationHandlerRegistry,
)
from synapse.federation.send_queue import FederationRemoteSendQueue
from synapse.federation.sender import FederationSender
from synapse.federation.transport.client import TransportLayerClient
from synapse.groups.attestations import GroupAttestationSigning, GroupAttestionRenewer
from synapse.groups.groups_server import GroupsServerHandler
from synapse.handlers import Handlers
from synapse.handlers.account_validity import AccountValidityHandler
from synapse.handlers.acme import AcmeHandler
from synapse.handlers.appservice import ApplicationServicesHandler
from synapse.handlers.auth import AuthHandler, MacaroonGenerator
from synapse.handlers.deactivate_account import DeactivateAccountHandler
from synapse.handlers.device import DeviceHandler, DeviceWorkerHandler
from synapse.handlers.devicemessage import DeviceMessageHandler
from synapse.handlers.e2e_keys import E2eKeysHandler
from synapse.handlers.e2e_room_keys import E2eRoomKeysHandler
from synapse.handlers.events import EventHandler, EventStreamHandler
from synapse.handlers.groups_local import GroupsLocalHandler
from synapse.handlers.initial_sync import InitialSyncHandler
from synapse.handlers.message import EventCreationHandler, MessageHandler
from synapse.handlers.pagination import PaginationHandler
from synapse.handlers.presence import PresenceHandler
from synapse.handlers.profile import BaseProfileHandler, MasterProfileHandler
from synapse.handlers.read_marker import ReadMarkerHandler
from synapse.handlers.receipts import ReceiptsHandler
from synapse.handlers.register import RegistrationHandler
from synapse.handlers.room import RoomContextHandler, RoomCreationHandler
from synapse.handlers.room_list import RoomListHandler
from synapse.handlers.room_member import RoomMemberMasterHandler
from synapse.handlers.room_member_worker import RoomMemberWorkerHandler
from synapse.handlers.set_password import SetPasswordHandler
from synapse.handlers.stats import StatsHandler
from synapse.handlers.sync import SyncHandler
from synapse.handlers.typing import TypingHandler
from synapse.handlers.user_directory import UserDirectoryHandler
from synapse.http.client import InsecureInterceptableContextFactory, SimpleHttpClient
from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.notifier import Notifier
from synapse.push.action_generator import ActionGenerator
from synapse.push.pusherpool import PusherPool
from synapse.rest.media.v1.media_repository import (
    MediaRepository,
    MediaRepositoryResource,
)
from synapse.secrets import Secrets
from synapse.server_notices.server_notices_manager import ServerNoticesManager
from synapse.server_notices.server_notices_sender import ServerNoticesSender
from synapse.server_notices.worker_server_notices_sender import (
    WorkerServerNoticesSender,
)
from synapse.state import StateHandler, StateResolutionHandler
from synapse.storage import DataStores, Storage
from synapse.streams.events import EventSources
from synapse.util import Clock
from synapse.util.distributor import Distributor

logger = logging.getLogger(__name__)


FuncType = Callable[..., Any]
F = TypeVar("F", bound=FuncType)


def builder(f: F) -> F:
    """Decorator to wrap a HomeServer method to cache result and detect
    cyclical dependencies.
    """
    if not f.__name__.startswith("get_"):
        raise Exception("Function must be named `get_*`")

    depname = f.__name__[len("get_") :]  # type: str

    @wraps(f)
    def _get(self):
        try:
            return getattr(self, depname)
        except AttributeError:
            pass

        # Prevent cyclic dependencies from deadlocking
        if depname in self._building:
            raise ValueError("Cyclic dependency while building %s" % (depname,))

        try:
            self._building[depname] = True
            dep = f(self)
        finally:
            self._building.pop(depname, None)

        setattr(self, self.depname, dep)

        return dep

    return cast(F, _get)


class HomeServer(object):
    """A basic homeserver object without lazy component builders.

    This will need all of the components it requires to either be passed as
    constructor arguments, or the relevant methods overriding to create them.
    Typically this would only be used for unit tests.

    Attributes:
        config (synapse.config.homeserver.HomeserverConfig):
        _listening_services (list[twisted.internet.tcp.Port]): TCP ports that
            we are listening on to provide HTTP services.
    """

    __metaclass__ = abc.ABCMeta

    REQUIRED_ON_MASTER_STARTUP = ["user_directory_handler", "stats_handler"]

    # This is overridden in derived application classes
    # (such as synapse.app.homeserver.SynapseHomeServer) and gives the class to be
    # instantiated during setup() for future return by get_datastore()
    DATASTORE_CLASS = abc.abstractproperty()

    def __init__(self, hostname: str, config: HomeServerConfig, reactor=None, **kwargs):
        """
        Args:
            hostname : The hostname for the server.
            config: The full config for the homeserver.
        """
        if not reactor:
            from twisted import internet

            reactor = internet.reactor

        self._reactor = reactor
        self.hostname = hostname
        self.config = config
        self._building = {}  # type: Dict[str, bool]
        self._listening_services = []  # type: List[tcp.Port]
        self.start_time = None  # type: Optional[int]

        self.clock = Clock(reactor)
        self.distributor = Distributor()
        self.ratelimiter = Ratelimiter()
        self.admin_redaction_ratelimiter = Ratelimiter()
        self.registration_ratelimiter = Ratelimiter()

        self.datastores = None  # type: Optional[DataStores]

        # Other kwargs are explicit dependencies
        for depname in kwargs:
            setattr(self, depname, kwargs[depname])

    def setup(self):
        logger.info("Setting up.")
        self.start_time = int(self.get_clock().time())
        self.datastores = DataStores(self.DATASTORE_CLASS, self)
        logger.info("Finished setting up.")

    def setup_master(self):
        """
        Some handlers have side effects on instantiation (like registering
        background updates). This function causes them to be fetched, and
        therefore instantiated, to run those side effects.
        """
        for i in self.REQUIRED_ON_MASTER_STARTUP:
            getattr(self, "get_" + i)()

    def get_reactor(self):
        """
        Fetch the Twisted reactor in use by this HomeServer.
        """
        return self._reactor

    def get_ip_from_request(self, request):
        # X-Forwarded-For is handled by our custom request type.
        return request.getClientIP()

    def is_mine(self, domain_specific_string) -> bool:
        return domain_specific_string.domain == self.hostname

    def is_mine_id(self, string: str) -> bool:
        return string.split(":", 1)[1] == self.hostname

    def get_clock(self) -> Clock:
        return self.clock

    def get_datastore(self):
        if not self.datastores:
            raise Exception("HomeServer has not been set up yet")

        return self.datastores.main

    def get_datastores(self) -> DataStores:
        if not self.datastores:
            raise Exception("HomeServer has not been set up yet")

        return self.datastores

    def get_config(self) -> HomeServerConfig:
        return self.config

    def get_distributor(self) -> Distributor:
        return self.distributor

    def get_ratelimiter(self) -> Ratelimiter:
        return self.ratelimiter

    def get_registration_ratelimiter(self) -> Ratelimiter:
        return self.registration_ratelimiter

    def get_admin_redaction_ratelimiter(self) -> Ratelimiter:
        return self.admin_redaction_ratelimiter

    @builder
    def get_federation_client(self) -> FederationClient:
        return FederationClient(self)

    @builder
    def get_federation_server(self) -> FederationServer:
        return FederationServer(self)

    @builder
    def get_handlers(self) -> Handlers:
        return Handlers(self)

    @builder
    def get_notifier(self) -> Notifier:
        return Notifier(self)

    @builder
    def get_auth(self) -> Auth:
        return Auth(self)

    @builder
    def get_http_client_context_factory(self) -> IPolicyForHTTPS:
        return (
            InsecureInterceptableContextFactory()
            if self.config.use_insecure_ssl_client_just_for_testing_do_not_use
            else BrowserLikePolicyForHTTPS()
        )

    @builder
    def get_simple_http_client(self) -> SimpleHttpClient:
        return SimpleHttpClient(self)

    @builder
    def get_proxied_http_client(self) -> SimpleHttpClient:
        return SimpleHttpClient(
            self,
            http_proxy=os.getenvb(b"http_proxy"),
            https_proxy=os.getenvb(b"HTTPS_PROXY"),
        )

    @builder
    def get_room_creation_handler(self) -> RoomCreationHandler:
        return RoomCreationHandler(self)

    @builder
    def get_sendmail(self) -> sendmail:
        return sendmail

    @builder
    def get_state_handler(self) -> StateHandler:
        return StateHandler(self)

    @builder
    def get_state_resolution_handler(self) -> StateResolutionHandler:
        return StateResolutionHandler(self)

    @builder
    def get_presence_handler(self) -> PresenceHandler:
        return PresenceHandler(self)

    @builder
    def get_typing_handler(self) -> TypingHandler:
        return TypingHandler(self)

    @builder
    def get_sync_handler(self) -> SyncHandler:
        return SyncHandler(self)

    @builder
    def get_room_list_handler(self) -> RoomListHandler:
        return RoomListHandler(self)

    @builder
    def get_auth_handler(self) -> AuthHandler:
        return AuthHandler(self)

    @builder
    def get_macaroon_generator(self) -> MacaroonGenerator:
        return MacaroonGenerator(self)

    @builder
    def get_device_handler(self) -> DeviceWorkerHandler:
        if self.config.worker_app:
            return DeviceWorkerHandler(self)
        else:
            return DeviceHandler(self)

    @builder
    def get_device_message_handler(self) -> DeviceMessageHandler:
        return DeviceMessageHandler(self)

    @builder
    def get_e2e_keys_handler(self) -> E2eKeysHandler:
        return E2eKeysHandler(self)

    @builder
    def get_e2e_room_keys_handler(self) -> E2eRoomKeysHandler:
        return E2eRoomKeysHandler(self)

    @builder
    def get_acme_handler(self) -> AcmeHandler:
        return AcmeHandler(self)

    @builder
    def get_application_service_api(self) -> ApplicationServiceApi:
        return ApplicationServiceApi(self)

    @builder
    def get_application_service_scheduler(self) -> ApplicationServiceScheduler:
        return ApplicationServiceScheduler(self)

    @builder
    def get_application_service_handler(self) -> ApplicationServicesHandler:
        return ApplicationServicesHandler(self)

    @builder
    def get_event_handler(self) -> EventHandler:
        return EventHandler(self)

    @builder
    def get_event_stream_handler(self) -> EventStreamHandler:
        return EventStreamHandler(self)

    @builder
    def get_initial_sync_handler(self) -> InitialSyncHandler:
        return InitialSyncHandler(self)

    @builder
    def get_profile_handler(self):
        if self.config.worker_app:
            return BaseProfileHandler(self)
        else:
            return MasterProfileHandler(self)

    @builder
    def get_event_creation_handler(self) -> EventCreationHandler:
        return EventCreationHandler(self)

    @builder
    def get_deactivate_account_handler(self) -> DeactivateAccountHandler:
        return DeactivateAccountHandler(self)

    @builder
    def get_set_password_handler(self) -> SetPasswordHandler:
        return SetPasswordHandler(self)

    @builder
    def get_event_sources(self) -> EventSources:
        return EventSources(self)

    @builder
    def get_keyring(self) -> Keyring:
        return Keyring(self)

    @builder
    def get_event_builder_factory(self) -> EventBuilderFactory:
        return EventBuilderFactory(self)

    @builder
    def get_filtering(self) -> Filtering:
        return Filtering(self)

    @builder
    def get_pusherpool(self) -> PusherPool:
        return PusherPool(self)

    @builder
    def get_http_client(self) -> MatrixFederationHttpClient:
        tls_client_options_factory = context_factory.ClientTLSOptionsFactory(
            self.config
        )
        return MatrixFederationHttpClient(self, tls_client_options_factory)

    @builder
    def get_media_repository_resource(self) -> MediaRepositoryResource:
        # build the media repo resource. This indirects through the HomeServer
        # to ensure that we only have a single instance of
        return MediaRepositoryResource(self)

    @builder
    def get_media_repository(self) -> MediaRepository:
        return MediaRepository(self)

    @builder
    def get_federation_transport_client(self) -> TransportLayerClient:
        return TransportLayerClient(self)

    @builder
    def get_federation_sender(self):
        if self.should_send_federation():
            return FederationSender(self)
        elif not self.config.worker_app:
            return FederationRemoteSendQueue(self)
        else:
            raise Exception("Workers cannot send federation traffic")

    @builder
    def get_receipts_handler(self) -> ReceiptsHandler:
        return ReceiptsHandler(self)

    @builder
    def get_read_marker_handler(self) -> ReadMarkerHandler:
        return ReadMarkerHandler(self)

    @builder
    def get_tcp_replication(self):
        raise NotImplementedError()

    @builder
    def get_action_generator(self) -> ActionGenerator:
        return ActionGenerator(self)

    @builder
    def get_user_directory_handler(self) -> UserDirectoryHandler:
        return UserDirectoryHandler(self)

    @builder
    def get_groups_local_handler(self) -> GroupsLocalHandler:
        return GroupsLocalHandler(self)

    @builder
    def get_groups_server_handler(self) -> GroupsServerHandler:
        return GroupsServerHandler(self)

    @builder
    def get_groups_attestation_signing(self) -> GroupAttestationSigning:
        return GroupAttestationSigning(self)

    @builder
    def get_groups_attestation_renewer(self) -> GroupAttestionRenewer:
        return GroupAttestionRenewer(self)

    @builder
    def get_secrets(self):
        return Secrets()

    @builder
    def get_stats_handler(self) -> StatsHandler:
        return StatsHandler(self)

    @builder
    def get_spam_checker(self) -> SpamChecker:
        return SpamChecker(self)

    @builder
    def get_third_party_event_rules(self) -> ThirdPartyEventRules:
        return ThirdPartyEventRules(self)

    @builder
    def get_room_member_handler(self):
        if self.config.worker_app:
            return RoomMemberWorkerHandler(self)
        return RoomMemberMasterHandler(self)

    @builder
    def get_federation_registry(self):
        if self.config.worker_app:
            return ReplicationFederationHandlerRegistry(self)
        else:
            return FederationHandlerRegistry()

    @builder
    def get_server_notices_manager(self) -> ServerNoticesManager:
        if self.config.worker_app:
            raise Exception("Workers cannot send server notices")
        return ServerNoticesManager(self)

    @builder
    def get_server_notices_sender(self):
        if self.config.worker_app:
            return WorkerServerNoticesSender(self)
        return ServerNoticesSender(self)

    @builder
    def get_message_handler(self) -> MessageHandler:
        return MessageHandler(self)

    @builder
    def get_pagination_handler(self) -> PaginationHandler:
        return PaginationHandler(self)

    @builder
    def get_room_context_handler(self) -> RoomContextHandler:
        return RoomContextHandler(self)

    @builder
    def get_registration_handler(self) -> RegistrationHandler:
        return RegistrationHandler(self)

    @builder
    def get_account_validity_handler(self) -> AccountValidityHandler:
        return AccountValidityHandler(self)

    @builder
    def get_saml_handler(self) -> "synapse.handlers.saml_handler.SamlHandler":
        from synapse.handlers.saml_handler import SamlHandler

        return SamlHandler(self)

    @builder
    def get_event_client_serializer(self) -> EventClientSerializer:
        return EventClientSerializer(self)

    @builder
    def get_storage(self) -> Storage:
        if self.datastores is None:
            raise Exception("HomeServer has not been set up yet")

        return Storage(self, self.datastores)

    def remove_pusher(self, app_id: str, push_key: str, user_id: str):
        return self.get_pusherpool().remove_pusher(app_id, push_key, user_id)

    def should_send_federation(self) -> bool:
        "Should this server be sending federation traffic directly?"
        return self.config.send_federation and (
            not self.config.worker_app
            or self.config.worker_app == "synapse.app.federation_sender"
        )
