# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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
from synapse.federation import initialize_http_replication
from synapse.notifier import Notifier
from synapse.api.auth import Auth
from synapse.handlers import Handlers
from synapse.state import StateHandler
from synapse.storage import DataStore
from synapse.util import Clock
from synapse.util.distributor import Distributor
from synapse.util.lockutils import LockManager
from synapse.streams.events import EventSources
from synapse.api.ratelimiting import Ratelimiter
from synapse.crypto.keyring import Keyring
from synapse.push.pusherpool import PusherPool
from synapse.events.builder import EventBuilderFactory
from synapse.api.filtering import Filtering


class BaseHomeServer(object):
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
        'clock',
        'http_client',
        'db_name',
        'db_pool',
        'persistence_service',
        'replication_layer',
        'datastore',
        'handlers',
        'auth',
        'rest_servlet_factory',
        'state_handler',
        'room_lock_manager',
        'notifier',
        'distributor',
        'resource_for_client',
        'resource_for_client_v2_alpha',
        'resource_for_federation',
        'resource_for_web_client',
        'resource_for_content_repo',
        'resource_for_server_key',
        'resource_for_media_repository',
        'resource_for_app_services',
        'event_sources',
        'ratelimiter',
        'keyring',
        'pusherpool',
        'event_builder_factory',
        'filtering',
    ]

    def __init__(self, hostname, **kwargs):
        """
        Args:
            hostname : The hostname for the server.
        """
        self.hostname = hostname
        self._building = {}

        # Other kwargs are explicit dependencies
        for depname in kwargs:
            setattr(self, depname, kwargs[depname])

    @classmethod
    def _make_dependency_method(cls, depname):
        def _get(self):
            if hasattr(self, depname):
                return getattr(self, depname)

            if hasattr(self, "build_%s" % (depname)):
                # Prevent cyclic dependencies from deadlocking
                if depname in self._building:
                    raise ValueError("Cyclic dependency while building %s" % (
                        depname,
                    ))
                self._building[depname] = 1

                builder = getattr(self, "build_%s" % (depname))
                dep = builder()
                setattr(self, depname, dep)

                del self._building[depname]

                return dep

            raise NotImplementedError(
                "%s has no %s nor a builder for it" % (
                    type(self).__name__, depname,
                )
            )

        setattr(BaseHomeServer, "get_%s" % (depname), _get)

    def get_ip_from_request(self, request):
        # May be an X-Forwarding-For header depending on config
        ip_addr = request.getClientIP()
        if self.config.captcha_ip_origin_is_x_forwarded:
            # use the header
            if request.requestHeaders.hasHeader("X-Forwarded-For"):
                ip_addr = request.requestHeaders.getRawHeaders(
                    "X-Forwarded-For"
                )[0]

        return ip_addr

    def is_mine(self, domain_specific_string):
        return domain_specific_string.domain == self.hostname

# Build magic accessors for every dependency
for depname in BaseHomeServer.DEPENDENCIES:
    BaseHomeServer._make_dependency_method(depname)


class HomeServer(BaseHomeServer):
    """A homeserver object that will construct most of its dependencies as
    required.

    It still requires the following to be specified by the caller:
        resource_for_client
        resource_for_web_client
        resource_for_federation
        resource_for_content_repo
        http_client
        db_pool
    """

    def build_clock(self):
        return Clock()

    def build_replication_layer(self):
        return initialize_http_replication(self)

    def build_datastore(self):
        return DataStore(self)

    def build_handlers(self):
        return Handlers(self)

    def build_notifier(self):
        return Notifier(self)

    def build_auth(self):
        return Auth(self)

    def build_state_handler(self):
        return StateHandler(self)

    def build_room_lock_manager(self):
        return LockManager()

    def build_distributor(self):
        return Distributor()

    def build_event_sources(self):
        return EventSources(self)

    def build_ratelimiter(self):
        return Ratelimiter()

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
