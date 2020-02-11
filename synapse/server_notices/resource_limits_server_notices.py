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

from six import iteritems

from twisted.internet import defer

from synapse.api.constants import (
    EventTypes,
    ServerNoticeLimitReached,
    ServerNoticeMsgType,
)
from synapse.api.errors import AuthError, ResourceLimitError, SynapseError
from synapse.server_notices.server_notices_manager import SERVER_NOTICE_ROOM_TAG

logger = logging.getLogger(__name__)


class ResourceLimitsServerNotices(object):
    """ Keeps track of whether the server has reached it's resource limit and
    ensures that the client is kept up to date.
    """

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer):
        """
        self._server_notices_manager = hs.get_server_notices_manager()
        self._store = hs.get_datastore()
        self._auth = hs.get_auth()
        self._config = hs.config
        self._resouce_limited = False
        self._message_handler = hs.get_message_handler()
        self._state = hs.get_state_handler()

        self._notifier = hs.get_notifier()

    @defer.inlineCallbacks
    def maybe_send_server_notice_to_user(self, user_id):
        """Check if we need to send a notice to this user, this will be true in
        two cases.
        1. The server has reached its limit does not reflect this
        2. The room state indicates that the server has reached its limit when
        actually the server is fine

        Args:
            user_id (str): user to check

        Returns:
            Deferred
        """
        if self._config.hs_disabled is True:
            return

        if self._config.limit_usage_by_mau is False:
            return

        if not self._server_notices_manager.is_enabled():
            # Don't try and send server notices unles they've been enabled
            return

        timestamp = yield self._store.user_last_seen_monthly_active(user_id)
        if timestamp is None:
            # This user will be blocked from receiving the notice anyway.
            # In practice, not sure we can ever get here
            return

        # Determine current state of room

        room_id = yield self._server_notices_manager.get_notice_room_for_user(user_id)

        if not room_id:
            logger.warn("Failed to get server notices room")
            return

        yield self._check_and_set_tags(user_id, room_id)
        currently_blocked, ref_events = yield self._is_room_currently_blocked(room_id)

        try:
            # Normally should always pass in user_id if you have it, but in
            # this case are checking what would happen to other users if they
            # were to arrive.
            try:
                yield self._auth.check_auth_blocking()
                is_auth_blocking = False
            except ResourceLimitError as e:
                is_auth_blocking = True
                event_content = e.msg
                event_limit_type = e.limit_type

            if currently_blocked and not is_auth_blocking:
                # Room is notifying of a block, when it ought not to be.
                # Remove block notification
                content = {"pinned": ref_events}
                yield self._server_notices_manager.send_notice(
                    user_id, content, EventTypes.Pinned, ""
                )

            elif not currently_blocked and is_auth_blocking:
                # Room is not notifying of a block, when it ought to be.
                # Add block notification
                content = {
                    "body": event_content,
                    "msgtype": ServerNoticeMsgType,
                    "server_notice_type": ServerNoticeLimitReached,
                    "admin_contact": self._config.admin_contact,
                    "limit_type": event_limit_type,
                }
                event = yield self._server_notices_manager.send_notice(
                    user_id, content, EventTypes.Message
                )

                content = {"pinned": [event.event_id]}
                yield self._server_notices_manager.send_notice(
                    user_id, content, EventTypes.Pinned, ""
                )

        except SynapseError as e:
            logger.error("Error sending resource limits server notice: %s", e)

    @defer.inlineCallbacks
    def _check_and_set_tags(self, user_id, room_id):
        """
        Since server notices rooms were originally not with tags,
        important to check that tags have been set correctly
        Args:
            user_id(str): the user in question
            room_id(str): the server notices room for that user
        """
        tags = yield self._store.get_tags_for_room(user_id, room_id)
        need_to_set_tag = True
        if tags:
            if SERVER_NOTICE_ROOM_TAG in tags:
                # tag already present, nothing to do here
                need_to_set_tag = False
        if need_to_set_tag:
            max_id = yield self._store.add_tag_to_room(
                user_id, room_id, SERVER_NOTICE_ROOM_TAG, {}
            )
            self._notifier.on_new_event("account_data_key", max_id, users=[user_id])

    @defer.inlineCallbacks
    def _is_room_currently_blocked(self, room_id):
        """
        Determines if the room is currently blocked

        Args:
            room_id(str): The room id of the server notices room

        Returns:

            bool: Is the room currently blocked
            list: The list of pinned events that are unrelated to limit blocking
            This list can be used as a convenience in the case where the block
            is to be lifted and the remaining pinned event references need to be
            preserved
        """
        currently_blocked = False
        pinned_state_event = None
        try:
            pinned_state_event = yield self._state.get_current_state(
                room_id, event_type=EventTypes.Pinned
            )
        except AuthError:
            # The user has yet to join the server notices room
            pass

        referenced_events = []
        if pinned_state_event is not None:
            referenced_events = list(pinned_state_event.content.get("pinned", []))

        events = yield self._store.get_events(referenced_events)
        for event_id, event in iteritems(events):
            if event.type != EventTypes.Message:
                continue
            if event.content.get("msgtype") == ServerNoticeMsgType:
                currently_blocked = True
                # remove event in case we need to disable blocking later on.
                if event_id in referenced_events:
                    referenced_events.remove(event.event_id)

        defer.returnValue((currently_blocked, referenced_events))
