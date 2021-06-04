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
import functools
import logging
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    TypeVar,
    Union,
    cast,
)

import twisted.internet.tcp
from twisted.internet import defer
from twisted.mail.smtp import sendmail
from twisted.web.iweb import IPolicyForHTTPS

from synapse.api.auth import Auth
from synapse.api.filtering import Filtering
from synapse.api.ratelimiting import Ratelimiter
from synapse.appservice.api import ApplicationServiceApi
from synapse.appservice.scheduler import ApplicationServiceScheduler
from synapse.config.homeserver import HomeServerConfig
from synapse.crypto import context_factory
from synapse.crypto.context_factory import RegularPolicyForHTTPS
from synapse.crypto.keyring import Keyring
from synapse.events.builder import EventBuilderFactory
from synapse.events.presence_router import PresenceRouter
from synapse.events.spamcheck import SpamChecker
from synapse.events.third_party_rules import ThirdPartyEventRules
from synapse.events.utils import EventClientSerializer
from synapse.federation.federation_client import FederationClient
from synapse.federation.federation_server import (
    FederationHandlerRegistry,
    FederationServer,
)
from synapse.federation.send_queue import FederationRemoteSendQueue
from synapse.federation.sender import AbstractFederationSender, FederationSender
from synapse.federation.transport.client import TransportLayerClient
from synapse.groups.attestations import GroupAttestationSigning, GroupAttestionRenewer
from synapse.groups.groups_server import GroupsServerHandler, GroupsServerWorkerHandler
from synapse.handlers.account_data import AccountDataHandler
from synapse.handlers.account_validity import AccountValidityHandler
from synapse.handlers.acme import AcmeHandler
from synapse.handlers.admin import AdminHandler
from synapse.handlers.appservice import ApplicationServicesHandler
from synapse.handlers.auth import AuthHandler, MacaroonGenerator
from synapse.handlers.cas import CasHandler
from synapse.handlers.deactivate_account import DeactivateAccountHandler
from synapse.handlers.device import DeviceHandler, DeviceWorkerHandler
from synapse.handlers.devicemessage import DeviceMessageHandler
from synapse.handlers.directory import DirectoryHandler
from synapse.handlers.e2e_keys import E2eKeysHandler
from synapse.handlers.e2e_room_keys import E2eRoomKeysHandler
from synapse.handlers.event_auth import EventAuthHandler
from synapse.handlers.events import EventHandler, EventStreamHandler
from synapse.handlers.federation import FederationHandler
from synapse.handlers.groups_local import GroupsLocalHandler, GroupsLocalWorkerHandler
from synapse.handlers.identity import IdentityHandler
from synapse.handlers.initial_sync import InitialSyncHandler
from synapse.handlers.message import EventCreationHandler, MessageHandler
from synapse.handlers.pagination import PaginationHandler
from synapse.handlers.password_policy import PasswordPolicyHandler
from synapse.handlers.presence import (
    BasePresenceHandler,
    PresenceHandler,
    WorkerPresenceHandler,
)
from synapse.handlers.profile import ProfileHandler
from synapse.handlers.read_marker import ReadMarkerHandler
from synapse.handlers.receipts import ReceiptsHandler
from synapse.handlers.register import RegistrationHandler
from synapse.handlers.room import (
    RoomContextHandler,
    RoomCreationHandler,
    RoomShutdownHandler,
)
from synapse.handlers.room_list import RoomListHandler
from synapse.handlers.room_member import RoomMemberHandler, RoomMemberMasterHandler
from synapse.handlers.room_member_worker import RoomMemberWorkerHandler
from synapse.handlers.search import SearchHandler
from synapse.handlers.send_email import SendEmailHandler
from synapse.handlers.set_password import SetPasswordHandler
from synapse.handlers.space_summary import SpaceSummaryHandler
from synapse.handlers.sso import SsoHandler
from synapse.handlers.stats import StatsHandler
from synapse.handlers.sync import SyncHandler
from synapse.handlers.typing import FollowerTypingHandler, TypingWriterHandler
from synapse.handlers.user_directory import UserDirectoryHandler
from synapse.http.client import InsecureInterceptableContextFactory, SimpleHttpClient
from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.module_api import ModuleApi
from synapse.notifier import Notifier
from synapse.push.action_generator import ActionGenerator
from synapse.push.pusherpool import PusherPool
from synapse.replication.tcp.client import ReplicationDataHandler
from synapse.replication.tcp.external_cache import ExternalCache
from synapse.replication.tcp.handler import ReplicationCommandHandler
from synapse.replication.tcp.resource import ReplicationStreamer
from synapse.replication.tcp.streams import STREAMS_MAP, Stream
from synapse.rest.media.v1.media_repository import (
    MediaRepository,
    MediaRepositoryResource,
)
from synapse.server_notices.server_notices_manager import ServerNoticesManager
from synapse.server_notices.server_notices_sender import ServerNoticesSender
from synapse.server_notices.worker_server_notices_sender import (
    WorkerServerNoticesSender,
)
from synapse.state import StateHandler, StateResolutionHandler
from synapse.storage import Databases, DataStore, Storage
from synapse.streams.events import EventSources
from synapse.types import DomainSpecificString, ISynapseReactor
from synapse.util import Clock
from synapse.util.distributor import Distributor
from synapse.util.ratelimitutils import FederationRateLimiter
from synapse.util.stringutils import random_string

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from txredisapi import RedisProtocol

    from synapse.handlers.oidc import OidcHandler
    from synapse.handlers.saml import SamlHandler


T = TypeVar("T", bound=Callable[..., Any])


def cache_in_self(builder: T) -> T:
    """Wraps a function called e.g. `get_foo`, checking if `self.foo` exists and
    returning if so. If not, calls the given function and sets `self.foo` to it.

    Also ensures that dependency cycles throw an exception correctly, rather
    than overflowing the stack.
    """

    if not builder.__name__.startswith("get_"):
        raise Exception(
            "@cache_in_self can only be used on functions starting with `get_`"
        )

    # get_attr -> _attr
    depname = builder.__name__[len("get") :]

    building = [False]

    @functools.wraps(builder)
    def _get(self):
        try:
            return getattr(self, depname)
        except AttributeError:
            pass

        # Prevent cyclic dependencies from deadlocking
        if building[0]:
            raise ValueError("Cyclic dependency while building %s" % (depname,))

        building[0] = True
        try:
            dep = builder(self)
            setattr(self, depname, dep)
        finally:
            building[0] = False

        return dep

    # We cast here as we need to tell mypy that `_get` has the same signature as
    # `builder`.
    return cast(T, _get)


class HomeServer(metaclass=abc.ABCMeta):
    """A basic homeserver object without lazy component builders.

    This will need all of the components it requires to either be passed as
    constructor arguments, or the relevant methods overriding to create them.
    Typically this would only be used for unit tests.

    Dependencies should be added by creating a `def get_<depname>(self)`
    function, wrapping it in `@cache_in_self`.

    Attributes:
        config (synapse.config.homeserver.HomeserverConfig):
        _listening_services (list[twisted.internet.tcp.Port]): TCP ports that
            we are listening on to provide HTTP services.
    """

    REQUIRED_ON_BACKGROUND_TASK_STARTUP = [
        "account_validity",
        "auth",
        "deactivate_account",
        "message",
        "pagination",
        "profile",
        "stats",
    ]

    # This is overridden in derived application classes
    # (such as synapse.app.homeserver.SynapseHomeServer) and gives the class to be
    # instantiated during setup() for future return by get_datastore()
    DATASTORE_CLASS = abc.abstractproperty()

    def __init__(
        self,
        hostname: str,
        config: HomeServerConfig,
        reactor=None,
        version_string="Synapse",
    ):
        """
        Args:
            hostname : The hostname for the server.
            config: The full config for the homeserver.
        """
        if not reactor:
            from twisted.internet import reactor as _reactor

            reactor = _reactor

        self._reactor = reactor
        self.hostname = hostname
        # the key we use to sign events and requests
        self.signing_key = config.key.signing_key[0]
        self.config = config
        self._listening_services = []  # type: List[twisted.internet.tcp.Port]
        self.start_time = None  # type: Optional[int]

        self._instance_id = random_string(5)
        self._instance_name = config.worker.instance_name

        self.version_string = version_string

        self.datastores = None  # type: Optional[Databases]

    def get_instance_id(self) -> str:
        """A unique ID for this synapse process instance.

        This is used to distinguish running instances in worker-based
        deployments.
        """
        return self._instance_id

    def get_instance_name(self) -> str:
        """A unique name for this synapse process.

        Used to identify the process over replication and in config. Does not
        change over restarts.
        """
        return self._instance_name

    def setup(self) -> None:
        logger.info("Setting up.")
        self.start_time = int(self.get_clock().time())
        self.datastores = Databases(self.DATASTORE_CLASS, self)
        logger.info("Finished setting up.")

        # Register background tasks required by this server. This must be done
        # somewhat manually due to the background tasks not being registered
        # unless handlers are instantiated.
        if self.config.run_background_tasks:
            self.setup_background_tasks()

    def start_listening(self) -> None:
        """Start the HTTP, manhole, metrics, etc listeners

        Does nothing in this base class; overridden in derived classes to start the
        appropriate listeners.
        """
        pass

    def setup_background_tasks(self) -> None:
        """
        Some handlers have side effects on instantiation (like registering
        background updates). This function causes them to be fetched, and
        therefore instantiated, to run those side effects.
        """
        for i in self.REQUIRED_ON_BACKGROUND_TASK_STARTUP:
            getattr(self, "get_" + i + "_handler")()

    def get_reactor(self) -> ISynapseReactor:
        """
        Fetch the Twisted reactor in use by this HomeServer.
        """
        return self._reactor

    def is_mine(self, domain_specific_string: DomainSpecificString) -> bool:
        return domain_specific_string.domain == self.hostname

    def is_mine_id(self, string: str) -> bool:
        return string.split(":", 1)[1] == self.hostname

    @cache_in_self
    def get_clock(self) -> Clock:
        return Clock(self._reactor)

    def get_datastore(self) -> DataStore:
        if not self.datastores:
            raise Exception("HomeServer.setup must be called before getting datastores")

        return self.datastores.main

    def get_datastores(self) -> Databases:
        if not self.datastores:
            raise Exception("HomeServer.setup must be called before getting datastores")

        return self.datastores

    @cache_in_self
    def get_distributor(self) -> Distributor:
        return Distributor()

    @cache_in_self
    def get_registration_ratelimiter(self) -> Ratelimiter:
        return Ratelimiter(
            store=self.get_datastore(),
            clock=self.get_clock(),
            rate_hz=self.config.rc_registration.per_second,
            burst_count=self.config.rc_registration.burst_count,
        )

    @cache_in_self
    def get_federation_client(self) -> FederationClient:
        return FederationClient(self)

    @cache_in_self
    def get_federation_server(self) -> FederationServer:
        return FederationServer(self)

    @cache_in_self
    def get_notifier(self) -> Notifier:
        return Notifier(self)

    @cache_in_self
    def get_auth(self) -> Auth:
        return Auth(self)

    @cache_in_self
    def get_http_client_context_factory(self) -> IPolicyForHTTPS:
        if self.config.use_insecure_ssl_client_just_for_testing_do_not_use:
            return InsecureInterceptableContextFactory()
        return RegularPolicyForHTTPS()

    @cache_in_self
    def get_simple_http_client(self) -> SimpleHttpClient:
        """
        An HTTP client with no special configuration.
        """
        return SimpleHttpClient(self)

    @cache_in_self
    def get_proxied_http_client(self) -> SimpleHttpClient:
        """
        An HTTP client that uses configured HTTP(S) proxies.
        """
        return SimpleHttpClient(self, use_proxy=True)

    @cache_in_self
    def get_proxied_blacklisted_http_client(self) -> SimpleHttpClient:
        """
        An HTTP client that uses configured HTTP(S) proxies and blacklists IPs
        based on the IP range blacklist/whitelist.
        """
        return SimpleHttpClient(
            self,
            ip_whitelist=self.config.ip_range_whitelist,
            ip_blacklist=self.config.ip_range_blacklist,
            use_proxy=True,
        )

    @cache_in_self
    def get_federation_http_client(self) -> MatrixFederationHttpClient:
        """
        An HTTP client for federation.
        """
        tls_client_options_factory = context_factory.FederationPolicyForHTTPS(
            self.config
        )
        return MatrixFederationHttpClient(self, tls_client_options_factory)

    @cache_in_self
    def get_room_creation_handler(self) -> RoomCreationHandler:
        return RoomCreationHandler(self)

    @cache_in_self
    def get_room_shutdown_handler(self) -> RoomShutdownHandler:
        return RoomShutdownHandler(self)

    @cache_in_self
    def get_sendmail(self) -> Callable[..., defer.Deferred]:
        return sendmail

    @cache_in_self
    def get_state_handler(self) -> StateHandler:
        return StateHandler(self)

    @cache_in_self
    def get_state_resolution_handler(self) -> StateResolutionHandler:
        return StateResolutionHandler(self)

    @cache_in_self
    def get_presence_handler(self) -> BasePresenceHandler:
        if self.get_instance_name() in self.config.worker.writers.presence:
            return PresenceHandler(self)
        else:
            return WorkerPresenceHandler(self)

    @cache_in_self
    def get_typing_writer_handler(self) -> TypingWriterHandler:
        if self.config.worker.writers.typing == self.get_instance_name():
            return TypingWriterHandler(self)
        else:
            raise Exception("Workers cannot write typing")

    @cache_in_self
    def get_presence_router(self) -> PresenceRouter:
        return PresenceRouter(self)

    @cache_in_self
    def get_typing_handler(self) -> FollowerTypingHandler:
        if self.config.worker.writers.typing == self.get_instance_name():
            # Use get_typing_writer_handler to ensure that we use the same
            # cached version.
            return self.get_typing_writer_handler()
        else:
            return FollowerTypingHandler(self)

    @cache_in_self
    def get_sso_handler(self) -> SsoHandler:
        return SsoHandler(self)

    @cache_in_self
    def get_sync_handler(self) -> SyncHandler:
        return SyncHandler(self)

    @cache_in_self
    def get_room_list_handler(self) -> RoomListHandler:
        return RoomListHandler(self)

    @cache_in_self
    def get_auth_handler(self) -> AuthHandler:
        return AuthHandler(self)

    @cache_in_self
    def get_macaroon_generator(self) -> MacaroonGenerator:
        return MacaroonGenerator(self)

    @cache_in_self
    def get_device_handler(self):
        if self.config.worker_app:
            return DeviceWorkerHandler(self)
        else:
            return DeviceHandler(self)

    @cache_in_self
    def get_device_message_handler(self) -> DeviceMessageHandler:
        return DeviceMessageHandler(self)

    @cache_in_self
    def get_directory_handler(self) -> DirectoryHandler:
        return DirectoryHandler(self)

    @cache_in_self
    def get_e2e_keys_handler(self) -> E2eKeysHandler:
        return E2eKeysHandler(self)

    @cache_in_self
    def get_e2e_room_keys_handler(self) -> E2eRoomKeysHandler:
        return E2eRoomKeysHandler(self)

    @cache_in_self
    def get_acme_handler(self) -> AcmeHandler:
        return AcmeHandler(self)

    @cache_in_self
    def get_admin_handler(self) -> AdminHandler:
        return AdminHandler(self)

    @cache_in_self
    def get_application_service_api(self) -> ApplicationServiceApi:
        return ApplicationServiceApi(self)

    @cache_in_self
    def get_application_service_scheduler(self) -> ApplicationServiceScheduler:
        return ApplicationServiceScheduler(self)

    @cache_in_self
    def get_application_service_handler(self) -> ApplicationServicesHandler:
        return ApplicationServicesHandler(self)

    @cache_in_self
    def get_event_handler(self) -> EventHandler:
        return EventHandler(self)

    @cache_in_self
    def get_event_stream_handler(self) -> EventStreamHandler:
        return EventStreamHandler(self)

    @cache_in_self
    def get_federation_handler(self) -> FederationHandler:
        return FederationHandler(self)

    @cache_in_self
    def get_identity_handler(self) -> IdentityHandler:
        return IdentityHandler(self)

    @cache_in_self
    def get_initial_sync_handler(self) -> InitialSyncHandler:
        return InitialSyncHandler(self)

    @cache_in_self
    def get_profile_handler(self) -> ProfileHandler:
        return ProfileHandler(self)

    @cache_in_self
    def get_event_creation_handler(self) -> EventCreationHandler:
        return EventCreationHandler(self)

    @cache_in_self
    def get_deactivate_account_handler(self) -> DeactivateAccountHandler:
        return DeactivateAccountHandler(self)

    @cache_in_self
    def get_search_handler(self) -> SearchHandler:
        return SearchHandler(self)

    @cache_in_self
    def get_send_email_handler(self) -> SendEmailHandler:
        return SendEmailHandler(self)

    @cache_in_self
    def get_set_password_handler(self) -> SetPasswordHandler:
        return SetPasswordHandler(self)

    @cache_in_self
    def get_event_sources(self) -> EventSources:
        return EventSources(self)

    @cache_in_self
    def get_keyring(self) -> Keyring:
        return Keyring(self)

    @cache_in_self
    def get_event_builder_factory(self) -> EventBuilderFactory:
        return EventBuilderFactory(self)

    @cache_in_self
    def get_filtering(self) -> Filtering:
        return Filtering(self)

    @cache_in_self
    def get_pusherpool(self) -> PusherPool:
        return PusherPool(self)

    @cache_in_self
    def get_media_repository_resource(self) -> MediaRepositoryResource:
        # build the media repo resource. This indirects through the HomeServer
        # to ensure that we only have a single instance of
        return MediaRepositoryResource(self)

    @cache_in_self
    def get_media_repository(self) -> MediaRepository:
        return MediaRepository(self)

    @cache_in_self
    def get_federation_transport_client(self) -> TransportLayerClient:
        return TransportLayerClient(self)

    @cache_in_self
    def get_federation_sender(self) -> AbstractFederationSender:
        if self.should_send_federation():
            return FederationSender(self)
        elif not self.config.worker_app:
            return FederationRemoteSendQueue(self)
        else:
            raise Exception("Workers cannot send federation traffic")

    @cache_in_self
    def get_receipts_handler(self) -> ReceiptsHandler:
        return ReceiptsHandler(self)

    @cache_in_self
    def get_read_marker_handler(self) -> ReadMarkerHandler:
        return ReadMarkerHandler(self)

    @cache_in_self
    def get_tcp_replication(self) -> ReplicationCommandHandler:
        return ReplicationCommandHandler(self)

    @cache_in_self
    def get_action_generator(self) -> ActionGenerator:
        return ActionGenerator(self)

    @cache_in_self
    def get_user_directory_handler(self) -> UserDirectoryHandler:
        return UserDirectoryHandler(self)

    @cache_in_self
    def get_groups_local_handler(
        self,
    ) -> Union[GroupsLocalWorkerHandler, GroupsLocalHandler]:
        if self.config.worker_app:
            return GroupsLocalWorkerHandler(self)
        else:
            return GroupsLocalHandler(self)

    @cache_in_self
    def get_groups_server_handler(self):
        if self.config.worker_app:
            return GroupsServerWorkerHandler(self)
        else:
            return GroupsServerHandler(self)

    @cache_in_self
    def get_groups_attestation_signing(self) -> GroupAttestationSigning:
        return GroupAttestationSigning(self)

    @cache_in_self
    def get_groups_attestation_renewer(self) -> GroupAttestionRenewer:
        return GroupAttestionRenewer(self)

    @cache_in_self
    def get_stats_handler(self) -> StatsHandler:
        return StatsHandler(self)

    @cache_in_self
    def get_spam_checker(self) -> SpamChecker:
        return SpamChecker(self)

    @cache_in_self
    def get_third_party_event_rules(self) -> ThirdPartyEventRules:
        return ThirdPartyEventRules(self)

    @cache_in_self
    def get_room_member_handler(self) -> RoomMemberHandler:
        if self.config.worker_app:
            return RoomMemberWorkerHandler(self)
        return RoomMemberMasterHandler(self)

    @cache_in_self
    def get_federation_registry(self) -> FederationHandlerRegistry:
        return FederationHandlerRegistry(self)

    @cache_in_self
    def get_server_notices_manager(self) -> ServerNoticesManager:
        if self.config.worker_app:
            raise Exception("Workers cannot send server notices")
        return ServerNoticesManager(self)

    @cache_in_self
    def get_server_notices_sender(self) -> WorkerServerNoticesSender:
        if self.config.worker_app:
            return WorkerServerNoticesSender(self)
        return ServerNoticesSender(self)

    @cache_in_self
    def get_message_handler(self) -> MessageHandler:
        return MessageHandler(self)

    @cache_in_self
    def get_pagination_handler(self) -> PaginationHandler:
        return PaginationHandler(self)

    @cache_in_self
    def get_room_context_handler(self) -> RoomContextHandler:
        return RoomContextHandler(self)

    @cache_in_self
    def get_registration_handler(self) -> RegistrationHandler:
        return RegistrationHandler(self)

    @cache_in_self
    def get_account_validity_handler(self) -> AccountValidityHandler:
        return AccountValidityHandler(self)

    @cache_in_self
    def get_cas_handler(self) -> CasHandler:
        return CasHandler(self)

    @cache_in_self
    def get_saml_handler(self) -> "SamlHandler":
        from synapse.handlers.saml import SamlHandler

        return SamlHandler(self)

    @cache_in_self
    def get_oidc_handler(self) -> "OidcHandler":
        from synapse.handlers.oidc import OidcHandler

        return OidcHandler(self)

    @cache_in_self
    def get_event_client_serializer(self) -> EventClientSerializer:
        return EventClientSerializer(self)

    @cache_in_self
    def get_password_policy_handler(self) -> PasswordPolicyHandler:
        return PasswordPolicyHandler(self)

    @cache_in_self
    def get_storage(self) -> Storage:
        return Storage(self, self.get_datastores())

    @cache_in_self
    def get_replication_streamer(self) -> ReplicationStreamer:
        return ReplicationStreamer(self)

    @cache_in_self
    def get_replication_data_handler(self) -> ReplicationDataHandler:
        return ReplicationDataHandler(self)

    @cache_in_self
    def get_replication_streams(self) -> Dict[str, Stream]:
        return {stream.NAME: stream(self) for stream in STREAMS_MAP.values()}

    @cache_in_self
    def get_federation_ratelimiter(self) -> FederationRateLimiter:
        return FederationRateLimiter(self.get_clock(), config=self.config.rc_federation)

    @cache_in_self
    def get_module_api(self) -> ModuleApi:
        return ModuleApi(self, self.get_auth_handler())

    @cache_in_self
    def get_account_data_handler(self) -> AccountDataHandler:
        return AccountDataHandler(self)

    @cache_in_self
    def get_space_summary_handler(self) -> SpaceSummaryHandler:
        return SpaceSummaryHandler(self)

    @cache_in_self
    def get_event_auth_handler(self) -> EventAuthHandler:
        return EventAuthHandler(self)

    @cache_in_self
    def get_external_cache(self) -> ExternalCache:
        return ExternalCache(self)

    @cache_in_self
    def get_outbound_redis_connection(self) -> Optional["RedisProtocol"]:
        if not self.config.redis.redis_enabled:
            return None

        # We only want to import redis module if we're using it, as we have
        # `txredisapi` as an optional dependency.
        from synapse.replication.tcp.redis import lazyConnection

        logger.info(
            "Connecting to redis (host=%r port=%r) for external cache",
            self.config.redis_host,
            self.config.redis_port,
        )

        return lazyConnection(
            hs=self,
            host=self.config.redis_host,
            port=self.config.redis_port,
            password=self.config.redis.redis_password,
            reconnect=True,
        )

    def should_send_federation(self) -> bool:
        "Should this server be sending federation traffic directly?"
        return self.config.send_federation
