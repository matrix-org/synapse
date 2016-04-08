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
        asapi = ApplicationServiceApi(hs)
        self.appservice_handler = ApplicationServicesHandler(
            hs, asapi, AppServiceScheduler(
                clock=hs.get_clock(),
                store=hs.get_datastore(),
                as_api=asapi
            )
        )
        self.sync_handler = hs.get(SyncHandler)
        self.registration_handler = hs.get(RegistrationHandler)
        self.message_handler = hs.get(MessageHandler)
        self.room_creation_handler = hs.get(RoomCreationHandler)
        self.room_member_handler = hs.get(RoomMemberHandler)
        self.event_stream_handler = hs.get(EventStreamHandler)
        self.event_handler = hs.get(EventHandler)
        self.federation_handler = hs.get(FederationHandler)
        self.profile_handler = hs.get(ProfileHandler)
        self.presence_handler = hs.get(PresenceHandler)
        self.room_list_handler = hs.get(RoomListHandler)
        self.directory_handler = hs.get(DirectoryHandler)
        self.typing_notification_handler = hs.get(TypingNotificationHandler)
        self.admin_handler = hs.get(AdminHandler)
        self.receipts_handler = hs.get(ReceiptsHandler)
        self.auth_handler = hs.get(AuthHandler)
        self.identity_handler = hs.get(IdentityHandler)
        self.search_handler = hs.get(SearchHandler)
        self.room_context_handler = hs.get(RoomContextHandler)
