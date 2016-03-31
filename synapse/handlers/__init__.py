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

from synapse.appservice.scheduler import AppServiceScheduler
from synapse.appservice.api import ApplicationServiceApi
from .register import RegistrationHandler
from .room import (
    RoomCreationHandler, RoomListHandler, RoomContextHandler,
)
from .room_member import RoomMemberHandler
from .message import MessageHandler
from .events import EventStreamHandler, EventHandler
from .federation import FederationHandler
from .profile import ProfileHandler
from .presence import PresenceHandler
from .directory import DirectoryHandler
from .typing import TypingNotificationHandler
from .admin import AdminHandler
from .appservice import ApplicationServicesHandler
from .sync import SyncHandler
from .auth import AuthHandler
from .identity import IdentityHandler
from .receipts import ReceiptsHandler
from .search import SearchHandler


class Handlers(object):

    """ A collection of all the event handlers.

    There's no need to lazily create these; we'll just make them all eagerly
    at construction time.
    """

    def __init__(self, hs):
        self.registration_handler = RegistrationHandler(hs)
        self.message_handler = MessageHandler(hs)
        self.room_creation_handler = RoomCreationHandler(hs)
        self.room_member_handler = RoomMemberHandler(hs)
        self.event_stream_handler = EventStreamHandler(hs)
        self.event_handler = EventHandler(hs)
        self.federation_handler = FederationHandler(hs)
        self.profile_handler = ProfileHandler(hs)
        self.presence_handler = PresenceHandler(hs)
        self.room_list_handler = RoomListHandler(hs)
        self.directory_handler = DirectoryHandler(hs)
        self.typing_notification_handler = TypingNotificationHandler(hs)
        self.admin_handler = AdminHandler(hs)
        self.receipts_handler = ReceiptsHandler(hs)
        asapi = ApplicationServiceApi(hs)
        self.appservice_handler = ApplicationServicesHandler(
            hs, asapi, AppServiceScheduler(
                clock=hs.get_clock(),
                store=hs.get_datastore(),
                as_api=asapi
            )
        )
        self.sync_handler = SyncHandler(hs)
        self.auth_handler = AuthHandler(hs)
        self.identity_handler = IdentityHandler(hs)
        self.search_handler = SearchHandler(hs)
        self.room_context_handler = RoomContextHandler(hs)
