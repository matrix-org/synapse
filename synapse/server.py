# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
from synapse.federation.handler import FederationEventHandler
from synapse.api.events.factory import EventFactory
from synapse.api.notifier import Notifier
from synapse.api.auth import Auth
from synapse.handlers import Handlers
from synapse.rest import RestServletFactory
from synapse.state import StateHandler
from synapse.storage import DataStore
from synapse.types import UserID
from synapse.util import Clock
from synapse.util.distributor import Distributor
from synapse.util.lockutils import LockManager


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
        'http_server',
        'http_client',
        'db_pool',
        'persistence_service',
        'federation',
        'replication_layer',
        'datastore',
        'event_factory',
        'handlers',
        'auth',
        'rest_servlet_factory',
        'state_handler',
        'room_lock_manager',
        'notifier',
        'distributor',
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

    # Other utility methods
    def parse_userid(self, s):
        """Parse the string given by 's' as a User ID and return a UserID
        object."""
        return UserID.from_string(s, hs=self)

# Build magic accessors for every dependency
for depname in BaseHomeServer.DEPENDENCIES:
    BaseHomeServer._make_dependency_method(depname)


class HomeServer(BaseHomeServer):
    """A homeserver object that will construct most of its dependencies as
    required.

    It still requires the following to be specified by the caller:
        http_server
        http_client
        db_pool
    """

    def build_clock(self):
        return Clock()

    def build_replication_layer(self):
        return initialize_http_replication(self)

    def build_federation(self):
        return FederationEventHandler(self)

    def build_datastore(self):
        return DataStore(self)

    def build_event_factory(self):
        return EventFactory()

    def build_handlers(self):
        return Handlers(self)

    def build_notifier(self):
        return Notifier(self)

    def build_auth(self):
        return Auth(self)

    def build_rest_servlet_factory(self):
        return RestServletFactory(self)

    def build_state_handler(self):
        return StateHandler(self)

    def build_room_lock_manager(self):
        return LockManager()

    def build_distributor(self):
        return Distributor()

    def register_servlets(self):
        """Simply building the ServletFactory is sufficient to have it
        register."""
        self.get_rest_servlet_factory()
