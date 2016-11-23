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

from .register import RegistrationHandler
from .room import (
    RoomCreationHandler, RoomContextHandler,
)
from .room_member import RoomMemberHandler
from .message import MessageHandler
from .federation import FederationHandler
from .profile import ProfileHandler
from .directory import DirectoryHandler
from .admin import AdminHandler
from .identity import IdentityHandler
from .search import SearchHandler


class Handlers(object):

    """ Deprecated. A collection of handlers.

    At some point most of the classes whose name ended "Handler" were
    accessed through this class.

    However this makes it painful to unit test the handlers and to run cut
    down versions of synapse that only use specific handlers because using a
    single handler required creating all of the handlers. So some of the
    handlers have been lifted out of the Handlers object and are now accessed
    directly through the homeserver object itself.

    Any new handlers should follow the new pattern of being accessed through
    the homeserver object and should not be added to the Handlers object.

    The remaining handlers should be moved out of the handlers object.
    """

    def __init__(self, hs):
        self.registration_handler = RegistrationHandler(hs)
        self.message_handler = MessageHandler(hs)
        self.room_creation_handler = RoomCreationHandler(hs)
        self.room_member_handler = RoomMemberHandler(hs)
        self.federation_handler = FederationHandler(hs)
        self.profile_handler = ProfileHandler(hs)
        self.directory_handler = DirectoryHandler(hs)
        self.admin_handler = AdminHandler(hs)
        self.identity_handler = IdentityHandler(hs)
        self.search_handler = SearchHandler(hs)
        self.room_context_handler = RoomContextHandler(hs)
