# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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
import logging

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership, RoomCreationPreset
from synapse.types import create_requester
from synapse.util.caches.descriptors import cachedInlineCallbacks

logger = logging.getLogger(__name__)

SERVER_NOTICE_ROOM_TAG = "m.server_notice"


class ServerNoticesManager(object):
    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer):
        """

        self._store = hs.get_datastore()
        self._config = hs.config
        self._room_creation_handler = hs.get_room_creation_handler()
        self._event_creation_handler = hs.get_event_creation_handler()
        self._is_mine_id = hs.is_mine_id

        self._notifier = hs.get_notifier()

    def is_enabled(self):
        """Checks if server notices are enabled on this server.

        Returns:
            bool
        """
        return self._config.server_notices_mxid is not None

    @defer.inlineCallbacks
    def send_notice(
        self, user_id, event_content, type=EventTypes.Message, state_key=None
    ):
        """Send a notice to the given user

        Creates the server notices room, if none exists.

        Args:
            user_id (str): mxid of user to send event to.
            event_content (dict): content of event to send
            type(EventTypes): type of event
            is_state_event(bool): Is the event a state event

        Returns:
            Deferred[FrozenEvent]
        """
        room_id = yield self.get_notice_room_for_user(user_id)

        system_mxid = self._config.server_notices_mxid
        requester = create_requester(system_mxid)

        logger.info("Sending server notice to %s", user_id)

        event_dict = {
            "type": type,
            "room_id": room_id,
            "sender": system_mxid,
            "content": event_content,
        }

        if state_key is not None:
            event_dict["state_key"] = state_key

        res = yield self._event_creation_handler.create_and_send_nonmember_event(
            requester, event_dict, ratelimit=False
        )
        defer.returnValue(res)

    @cachedInlineCallbacks()
    def get_notice_room_for_user(self, user_id):
        """Get the room for notices for a given user

        If we have not yet created a notice room for this user, create it

        Args:
            user_id (str): complete user id for the user we want a room for

        Returns:
            str: room id of notice room.
        """
        if not self.is_enabled():
            raise Exception("Server notices not enabled")

        assert self._is_mine_id(user_id), "Cannot send server notices to remote users"

        rooms = yield self._store.get_rooms_for_user_where_membership_is(
            user_id, [Membership.INVITE, Membership.JOIN]
        )
        system_mxid = self._config.server_notices_mxid
        for room in rooms:
            # it's worth noting that there is an asymmetry here in that we
            # expect the user to be invited or joined, but the system user must
            # be joined. This is kinda deliberate, in that if somebody somehow
            # manages to invite the system user to a room, that doesn't make it
            # the server notices room.
            user_ids = yield self._store.get_users_in_room(room.room_id)
            if system_mxid in user_ids:
                # we found a room which our user shares with the system notice
                # user
                logger.info("Using room %s", room.room_id)
                defer.returnValue(room.room_id)

        # apparently no existing notice room: create a new one
        logger.info("Creating server notices room for %s", user_id)

        # see if we want to override the profile info for the server user.
        # note that if we want to override either the display name or the
        # avatar, we have to use both.
        join_profile = None
        if (
            self._config.server_notices_mxid_display_name is not None
            or self._config.server_notices_mxid_avatar_url is not None
        ):
            join_profile = {
                "displayname": self._config.server_notices_mxid_display_name,
                "avatar_url": self._config.server_notices_mxid_avatar_url,
            }

        requester = create_requester(system_mxid)
        info = yield self._room_creation_handler.create_room(
            requester,
            config={
                "preset": RoomCreationPreset.PRIVATE_CHAT,
                "name": self._config.server_notices_room_name,
                "power_level_content_override": {"users_default": -10},
                "invite": (user_id,),
            },
            ratelimit=False,
            creator_join_profile=join_profile,
        )
        room_id = info["room_id"]

        max_id = yield self._store.add_tag_to_room(
            user_id, room_id, SERVER_NOTICE_ROOM_TAG, {}
        )
        self._notifier.on_new_event("account_data_key", max_id, users=[user_id])

        logger.info("Created server notices room %s for %s", room_id, user_id)
        defer.returnValue(room_id)
