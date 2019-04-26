# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from twisted.enterprise import adbapi
from twisted.mail.smtp import sendmail
from twisted.web.client import BrowserLikePolicyForHTTPS

from synapse.api.auth import Auth
from synapse.api.filtering import Filtering
from synapse.api.ratelimiting import Ratelimiter
from synapse.appservice.api import ApplicationServiceApi
from synapse.appservice.scheduler import ApplicationServiceScheduler
from synapse.crypto import context_factory
from synapse.crypto.keyring import Keyring
from synapse.events.builder import EventBuilderFactory
from synapse.events.spamcheck import SpamChecker
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
from synapse.server_notices.worker_server_notices_sender import WorkerServerNoticesSender
from synapse.state import StateHandler, StateResolutionHandler
from synapse.streams.events import EventSources
from synapse.util import Clock
from synapse.util.distributor import Distributor

logger = logging.getLogger(__name__)


class HomeServer(object):
    """A basic homeserver object without lazy component builders.

    This will need all of the components it requires to either be passed as
    constructor arguments, or the relevant methods overriding to create them.
    Typically this would only be used for unit tests.

    For every dependency in the DEPENDENCIES list below, this class creates one
    method,
        def get_DEPENDENCY(self)
    which returns the value of that dependency. If no value has yet been set
    nor was provided to the constructor, it will attempt to call a lazy builder
    method called
        def build_DEPENDENCY(self)
    which must be implemented by the subclass. This code may call any of the
    required "get" methods on the instance to obtain the sub-dependencies that
    one requires.

    Attributes:
        config (synapse.config.homeserver.HomeserverConfig):
        _listening_services (list[twisted.internet.tcp.Port]): TCP ports that
            we are listening on to provide HTTP services.
    """

    __metaclass__ = abc.ABCMeta

    DEPENDENCIES = [
        'http_client',
        'db_pool',
        'federation_client',
        'federation_server',
        'handlers',
        'auth',
        'room_creation_handler',
        'state_handler',
        'state_resolution_handler',
        'presence_handler',
        'sync_handler',
        'typing_handler',
        'room_list_handler',
        'acme_handler',
        'auth_handler',
        'device_handler',
        'e2e_keys_handler',
        'e2e_room_keys_handler',
        'event_handler',
        'event_stream_handler',
        'initial_sync_handler',
        'application_service_api',
        'application_service_scheduler',
        'application_service_handler',
        'device_message_handler',
        'profile_handler',
        'event_creation_handler',
        'deactivate_account_handler',
        'set_password_handler',
        'notifier',
        'event_sources',
        'keyring',
        'pusherpool',
        'event_builder_factory',
        'filtering',
        'http_client_context_factory',
        'simple_http_client',
        'media_repository',
        'media_repository_resource',
        'federation_transport_client',
        'federation_sender',
        'receipts_handler',
        'macaroon_generator',
        'tcp_replication',
        'read_marker_handler',
        'action_generator',
        'user_directory_handler',
        'groups_local_handler',
        'groups_server_handler',
        'groups_attestation_signing',
        'groups_attestation_renewer',
        'secrets',
        'spam_checker',
        'room_member_handler',
        'federation_registry',
        'server_notices_manager',
        'server_notices_sender',
        'message_handler',
        'pagination_handler',
        'room_context_handler',
        'sendmail',
        'registration_handler',
        'account_validity_handler',
    ]

    REQUIRED_ON_MASTER_STARTUP = [
        "user_directory_handler",
    ]

    # This is overridden in derived application classes
    # (such as synapse.app.homeserver.SynapseHomeServer) and gives the class to be
    # instantiated during setup() for future return by get_datastore()
    DATASTORE_CLASS = abc.abstractproperty()

    def __init__(self, hostname, reactor=None, **kwargs):
        """
        Args:
            hostname : The hostname for the server.
        """
        if not reactor:
            from twisted.internet import reactor

        self._reactor = reactor
        self.hostname = hostname
        self._building = {}
        self._listening_services = []

        self.clock = Clock(reactor)
        self.distributor = Distributor()
        self.ratelimiter = Ratelimiter()
        self.registration_ratelimiter = Ratelimiter()

        self.datastore = None

        # Other kwargs are explicit dependencies
        for depname in kwargs:
            setattr(self, depname, kwargs[depname])

    def setup(self):
        logger.info("Setting up.")
        with self.get_db_conn() as conn:
            self.datastore = self.DATASTORE_CLASS(conn, self)
            conn.commit()
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

    def is_mine(self, domain_specific_string):
        return domain_specific_string.domain == self.hostname

    def is_mine_id(self, string):
        return string.split(":", 1)[1] == self.hostname

    def get_clock(self):
        return self.clock

    def get_datastore(self):
        return self.datastore

    def get_config(self):
        return self.config

    def get_distributor(self):
        return self.distributor

    def get_ratelimiter(self):
        return self.ratelimiter

    def get_registration_ratelimiter(self):
        return self.registration_ratelimiter

    def build_federation_client(self):
        return FederationClient(self)

    def build_federation_server(self):
        return FederationServer(self)

    def build_handlers(self):
        return Handlers(self)

    def build_notifier(self):
        return Notifier(self)

    def build_auth(self):
        return Auth(self)

    def build_http_client_context_factory(self):
        return (
            InsecureInterceptableContextFactory()
            if self.config.use_insecure_ssl_client_just_for_testing_do_not_use
            else BrowserLikePolicyForHTTPS()
        )

    def build_simple_http_client(self):
        return SimpleHttpClient(self)

    def build_room_creation_handler(self):
        return RoomCreationHandler(self)

    def build_sendmail(self):
        return sendmail

    def build_state_handler(self):
        return StateHandler(self)

    def build_state_resolution_handler(self):
        return StateResolutionHandler(self)

    def build_presence_handler(self):
        return PresenceHandler(self)

    def build_typing_handler(self):
        return TypingHandler(self)

    def build_sync_handler(self):
        return SyncHandler(self)

    def build_room_list_handler(self):
        return RoomListHandler(self)

    def build_auth_handler(self):
        return AuthHandler(self)

    def build_macaroon_generator(self):
        return MacaroonGenerator(self)

    def build_device_handler(self):
        if self.config.worker_app:
            return DeviceWorkerHandler(self)
        else:
            return DeviceHandler(self)

    def build_device_message_handler(self):
        return DeviceMessageHandler(self)

    def build_e2e_keys_handler(self):
        return E2eKeysHandler(self)

    def build_e2e_room_keys_handler(self):
        return E2eRoomKeysHandler(self)

    def build_acme_handler(self):
        return AcmeHandler(self)

    def build_application_service_api(self):
        return ApplicationServiceApi(self)

    def build_application_service_scheduler(self):
        return ApplicationServiceScheduler(self)

    def build_application_service_handler(self):
        return ApplicationServicesHandler(self)

    def build_event_handler(self):
        return EventHandler(self)

    def build_event_stream_handler(self):
        return EventStreamHandler(self)

    def build_initial_sync_handler(self):
        return InitialSyncHandler(self)

    def build_profile_handler(self):
        if self.config.worker_app:
            return BaseProfileHandler(self)
        else:
            return MasterProfileHandler(self)

    def build_event_creation_handler(self):
        return EventCreationHandler(self)

    def build_deactivate_account_handler(self):
        return DeactivateAccountHandler(self)

    def build_set_password_handler(self):
        return SetPasswordHandler(self)

    def build_event_sources(self):
        return EventSources(self)

    def build_keyring(self):
        return Keyring(self)

    def build_event_builder_factory(self):
        return EventBuilderFactory(self)

    def build_filtering(self):
        return Filtering(self)

    def build_pusherpool(self):
        return PusherPool(self)

    def build_http_client(self):
        tls_client_options_factory = context_factory.ClientTLSOptionsFactory(
            self.config
        )
        return MatrixFederationHttpClient(self, tls_client_options_factory)

    def build_db_pool(self):
        name = self.db_config["name"]

        return adbapi.ConnectionPool(
            name,
            cp_reactor=self.get_reactor(),
            **self.db_config.get("args", {})
        )

    def get_db_conn(self, run_new_connection=True):
        """Makes a new connection to the database, skipping the db pool

        Returns:
            Connection: a connection object implementing the PEP-249 spec
        """
        # Any param beginning with cp_ is a parameter for adbapi, and should
        # not be passed to the database engine.
        db_params = {
            k: v for k, v in self.db_config.get("args", {}).items()
            if not k.startswith("cp_")
        }
        db_conn = self.database_engine.module.connect(**db_params)
        if run_new_connection:
            self.database_engine.on_new_connection(db_conn)
        return db_conn

    def build_media_repository_resource(self):
        # build the media repo resource. This indirects through the HomeServer
        # to ensure that we only have a single instance of
        return MediaRepositoryResource(self)

    def build_media_repository(self):
        return MediaRepository(self)

    def build_federation_transport_client(self):
        return TransportLayerClient(self)

    def build_federation_sender(self):
        if self.should_send_federation():
            return FederationSender(self)
        elif not self.config.worker_app:
            return FederationRemoteSendQueue(self)
        else:
            raise Exception("Workers cannot send federation traffic")

    def build_receipts_handler(self):
        return ReceiptsHandler(self)

    def build_read_marker_handler(self):
        return ReadMarkerHandler(self)

    def build_tcp_replication(self):
        raise NotImplementedError()

    def build_action_generator(self):
        return ActionGenerator(self)

    def build_user_directory_handler(self):
        return UserDirectoryHandler(self)

    def build_groups_local_handler(self):
        return GroupsLocalHandler(self)

    def build_groups_server_handler(self):
        return GroupsServerHandler(self)

    def build_groups_attestation_signing(self):
        return GroupAttestationSigning(self)

    def build_groups_attestation_renewer(self):
        return GroupAttestionRenewer(self)

    def build_secrets(self):
        return Secrets()

    def build_spam_checker(self):
        return SpamChecker(self)

    def build_room_member_handler(self):
        if self.config.worker_app:
            return RoomMemberWorkerHandler(self)
        return RoomMemberMasterHandler(self)

    def build_federation_registry(self):
        if self.config.worker_app:
            return ReplicationFederationHandlerRegistry(self)
        else:
            return FederationHandlerRegistry()

    def build_server_notices_manager(self):
        if self.config.worker_app:
            raise Exception("Workers cannot send server notices")
        return ServerNoticesManager(self)

    def build_server_notices_sender(self):
        if self.config.worker_app:
            return WorkerServerNoticesSender(self)
        return ServerNoticesSender(self)

    def build_message_handler(self):
        return MessageHandler(self)

    def build_pagination_handler(self):
        return PaginationHandler(self)

    def build_room_context_handler(self):
        return RoomContextHandler(self)

    def build_registration_handler(self):
        return RegistrationHandler(self)

    def build_account_validity_handler(self):
        return AccountValidityHandler(self)

    def remove_pusher(self, app_id, push_key, user_id):
        return self.get_pusherpool().remove_pusher(app_id, push_key, user_id)

    def should_send_federation(self):
        "Should this server be sending federation traffic directly?"
        return self.config.send_federation and (
            not self.config.worker_app
            or self.config.worker_app == "synapse.app.federation_sender"
        )


def _make_dependency_method(depname):
    def _get(hs):
        try:
            return getattr(hs, depname)
        except AttributeError:
            pass

        try:
            builder = getattr(hs, "build_%s" % (depname))
        except AttributeError:
            builder = None

        if builder:
            # Prevent cyclic dependencies from deadlocking
            if depname in hs._building:
                raise ValueError("Cyclic dependency while building %s" % (
                    depname,
                ))
            hs._building[depname] = 1

            dep = builder()
            setattr(hs, depname, dep)

            del hs._building[depname]

            return dep

        raise NotImplementedError(
            "%s has no %s nor a builder for it" % (
                type(hs).__name__, depname,
            )
        )

    setattr(HomeServer, "get_%s" % (depname), _get)


# Build magic accessors for every dependency
for depname in HomeServer.DEPENDENCIES:
    _make_dependency_method(depname)
