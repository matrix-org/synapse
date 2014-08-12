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
from .register import RegistrationHandler
from .room import (
    MessageHandler, RoomCreationHandler, RoomMemberHandler, RoomListHandler
)
from .events import EventStreamHandler
from .federation import FederationHandler
from .login import LoginHandler
from .profile import ProfileHandler
from .presence import PresenceHandler
from .directory import DirectoryHandler


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
        self.federation_handler = FederationHandler(hs)
        self.profile_handler = ProfileHandler(hs)
        self.presence_handler = PresenceHandler(hs)
        self.room_list_handler = RoomListHandler(hs)
        self.login_handler = LoginHandler(hs)
        self.directory_handler = DirectoryHandler(hs)
