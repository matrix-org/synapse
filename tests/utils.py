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

from synapse.http.server import HttpServer
from synapse.api.errors import cs_error, CodeMessageException, StoreError
from synapse.api.constants import Membership

from synapse.api.events.room import (
    RoomMemberEvent, MessageEvent
)

from twisted.internet import defer

from collections import namedtuple
from mock import patch, Mock
import json
import urlparse


class MockHttpServer(HttpServer):

    def __init__(self, prefix=""):
        self.callbacks = []  # 3-tuple of method/pattern/function
        self.prefix = prefix

    def trigger_get(self, path):
        return self.trigger("GET", path, None)

    @patch('twisted.web.http.Request')
    @defer.inlineCallbacks
    def trigger(self, http_method, path, content, mock_request):
        """ Fire an HTTP event.

        Args:
            http_method : The HTTP method
            path : The HTTP path
            content : The HTTP body
            mock_request : Mocked request to pass to the event so it can get
                           content.
        Returns:
            A tuple of (code, response)
        Raises:
            KeyError If no event is found which will handle the path.
        """
        path = self.prefix + path

        # annoyingly we return a twisted http request which has chained calls
        # to get at the http content, hence mock it here.
        mock_content = Mock()
        config = {'read.return_value': content}
        mock_content.configure_mock(**config)
        mock_request.content = mock_content

        # return the right path if the event requires it
        mock_request.path = path

        # add in query params to the right place
        try:
            mock_request.args = urlparse.parse_qs(path.split('?')[1])
            mock_request.path = path.split('?')[0]
            path = mock_request.path
        except:
            pass

        for (method, pattern, func) in self.callbacks:
            if http_method != method:
                continue

            matcher = pattern.match(path)
            if matcher:
                try:
                    (code, response) = yield func(
                        mock_request,
                        *matcher.groups()
                    )
                    defer.returnValue((code, response))
                except CodeMessageException as e:
                    defer.returnValue((e.code, cs_error(e.msg)))

        raise KeyError("No event can handle %s" % path)

    def register_path(self, method, path_pattern, callback):
        self.callbacks.append((method, path_pattern, callback))


class MockClock(object):
    now = 1000

    def time(self):
        return self.now

    def time_msec(self):
        return self.time() * 1000

    # For unit testing
    def advance_time(self, secs):
        self.now += secs


class MemoryDataStore(object):

    Room = namedtuple(
        "Room",
        ["room_id", "is_public", "creator"]
    )

    def __init__(self):
        self.tokens_to_users = {}
        self.paths_to_content = {}

        self.members = {}
        self.rooms = {}

        self.current_state = {}
        self.events = []

    def register(self, user_id, token, password_hash):
        if user_id in self.tokens_to_users.values():
            raise StoreError(400, "User in use.")
        self.tokens_to_users[token] = user_id

    def get_user_by_token(self, token):
        try:
            return self.tokens_to_users[token]
        except:
            raise StoreError(400, "User does not exist.")

    def get_room(self, room_id):
        try:
            return self.rooms[room_id]
        except:
            return None

    def store_room(self, room_id, room_creator_user_id, is_public):
        if room_id in self.rooms:
            raise StoreError(409, "Conflicting room!")

        room = MemoryDataStore.Room(
            room_id=room_id,
            is_public=is_public,
            creator=room_creator_user_id
        )
        self.rooms[room_id] = room

    def get_room_member(self, user_id, room_id):
        return self.members.get(room_id, {}).get(user_id)

    def get_room_members(self, room_id, membership=None):
        if membership:
            return [
                v for k, v in self.members.get(room_id, {}).items()
                if v.membership == membership
            ]
        else:
            return self.members.get(room_id, {}).values()

    def get_rooms_for_user_where_membership_is(self, user_id, membership_list):
        return [
            r for r in self.members
            if self.members[r].get(user_id).membership in membership_list
        ]

    def get_room_events_stream(self, user_id=None, from_key=None, to_key=None,
                            room_id=None, limit=0, with_feedback=False):
        return ([], from_key)  # TODO

    def get_joined_hosts_for_room(self, room_id):
        return defer.succeed([])

    def persist_event(self, event):
        if event.type == RoomMemberEvent.TYPE:
            room_id = event.room_id
            user = event.target_user_id
            membership = event.membership
            self.members.setdefault(room_id, {})[user] = event

        if hasattr(event, "state_key"):
            key = (event.room_id, event.type, event.state_key)
            self.current_state[key] = event

        self.events.append(event)

    def get_current_state(self, room_id, event_type=None, state_key=""):
        if event_type:
            key = (room_id, event_type, state_key)
            return self.current_state.get(key)
        else:
            return [
                e for e in self.current_state
                if e[0] == room_id
            ]

    def set_presence_state(self, user_localpart, state):
        return defer.succeed({"state": 0})

    def get_presence_list(self, user_localpart, accepted):
        return []

    def get_room_events_max_id(self):
        return 0  # TODO (erikj)
