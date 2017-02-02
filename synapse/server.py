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
import logging

from twisted.enterprise import adbapi
from twisted.web.client import BrowserLikePolicyForHTTPS

from synapse.api.auth import Auth
from synapse.api.filtering import Filtering
from synapse.api.ratelimiting import Ratelimiter
from synapse.appservice.api import ApplicationServiceApi
from synapse.appservice.scheduler import ApplicationServiceScheduler
from synapse.crypto.keyring import Keyring
from synapse.events.builder import EventBuilderFactory
from synapse.federation import initialize_http_replication
from synapse.federation.send_queue import FederationRemoteSendQueue
from synapse.federation.transport.client import TransportLayerClient
from synapse.federation.transaction_queue import TransactionQueue
from synapse.handlers import Handlers
from synapse.handlers.appservice import ApplicationServicesHandler
from synapse.handlers.auth import AuthHandler, MacaroonGeneartor
from synapse.handlers.devicemessage import DeviceMessageHandler
from synapse.handlers.device import DeviceHandler
from synapse.handlers.e2e_keys import E2eKeysHandler
from synapse.handlers.presence import PresenceHandler
from synapse.handlers.room_list import RoomListHandler
from synapse.handlers.sync import SyncHandler
from synapse.handlers.typing import TypingHandler
from synapse.handlers.events import EventHandler, EventStreamHandler
from synapse.handlers.initial_sync import InitialSyncHandler
from synapse.handlers.receipts import ReceiptsHandler
from synapse.http.client import SimpleHttpClient, InsecureInterceptableContextFactory
from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.notifier import Notifier
from synapse.push.pusherpool import PusherPool
from synapse.rest.media.v1.media_repository import MediaRepository
from synapse.state import StateHandler
from synapse.storage import DataStore
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
    """

    DEPENDENCIES = [
        'config',
        'clock',
        'http_client',
        'db_pool',
        'persistence_service',
        'replication_layer',
        'datastore',
        'handlers',
        'v1auth',
        'auth',
        'rest_servlet_factory',
        'state_handler',
        'presence_handler',
        'sync_handler',
        'typing_handler',
        'room_list_handler',
        'auth_handler',
        'device_handler',
        'e2e_keys_handler',
        'event_handler',
        'event_stream_handler',
        'initial_sync_handler',
        'application_service_api',
        'application_service_scheduler',
        'application_service_handler',
        'device_message_handler',
        'notifier',
        'distributor',
        'client_resource',
        'resource_for_federation',
        'resource_for_static_content',
        'resource_for_web_client',
        'resource_for_content_repo',
        'resource_for_server_key',
        'resource_for_server_key_v2',
        'resource_for_media_repository',
        'resource_for_metrics',
        'event_sources',
        'ratelimiter',
        'keyring',
        'pusherpool',
        'event_builder_factory',
        'filtering',
        'http_client_context_factory',
        'simple_http_client',
        'media_repository',
        'federation_transport_client',
        'federation_sender',
        'receipts_handler',
        'macaroon_generator',
    ]

    def __init__(self, hostname, **kwargs):
        """
        Args:
            hostname : The hostname for the server.
        """
        self.hostname = hostname
        self._building = {}

        self.clock = Clock()
        self.distributor = Distributor()
        self.ratelimiter = Ratelimiter()

        # Other kwargs are explicit dependencies
        for depname in kwargs:
            setattr(self, depname, kwargs[depname])

    def setup(self):
        logger.info("Setting up.")
        self.datastore = DataStore(self.get_db_conn(), self)
        logger.info("Finished setting up.")

    def get_ip_from_request(self, request):
        # X-Forwarded-For is handled by our custom request type.
        return request.getClientIP()

    def is_mine(self, domain_specific_string):
        return domain_specific_string.domain == self.hostname

    def is_mine_id(self, string):
        return string.split(":", 1)[1] == self.hostname

    def build_replication_layer(self):
        return initialize_http_replication(self)

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

    def build_v1auth(self):
        orf = Auth(self)
        # Matrix spec makes no reference to what HTTP status code is returned,
        # but the V1 API uses 403 where it means 401, and the webclient
        # relies on this behaviour, so V1 gets its own copy of the auth
        # with backwards compat behaviour.
        orf.TOKEN_NOT_FOUND_HTTP_STATUS = 403
        return orf

    def build_state_handler(self):
        return StateHandler(self)

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
        return MacaroonGeneartor(self)

    def build_device_handler(self):
        return DeviceHandler(self)

    def build_device_message_handler(self):
        return DeviceMessageHandler(self)

    def build_e2e_keys_handler(self):
        return E2eKeysHandler(self)

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

    def build_event_sources(self):
        return EventSources(self)

    def build_keyring(self):
        return Keyring(self)

    def build_event_builder_factory(self):
        return EventBuilderFactory(
            clock=self.get_clock(),
            hostname=self.hostname,
        )

    def build_filtering(self):
        return Filtering(self)

    def build_pusherpool(self):
        return PusherPool(self)

    def build_http_client(self):
        return MatrixFederationHttpClient(self)

    def build_db_pool(self):
        name = self.db_config["name"]

        return adbapi.ConnectionPool(
            name,
            **self.db_config.get("args", {})
        )

    def build_media_repository(self):
        return MediaRepository(self)

    def build_federation_transport_client(self):
        return TransportLayerClient(self)

    def build_federation_sender(self):
        if self.should_send_federation():
            return TransactionQueue(self)
        elif not self.config.worker_app:
            return FederationRemoteSendQueue(self)
        else:
            raise Exception("Workers cannot send federation traffic")

    def build_receipts_handler(self):
        return ReceiptsHandler(self)

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
