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

from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError, SynapseError
from synapse.server_notices.server_notices_manager import SERVER_NOTICE_ROOM_TAG

logger = logging.getLogger(__name__)


class ResourceLimitsServerNotices(object):
    """
    """
    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer):
        """
        self._server_notices_manager = hs.get_server_notices_manager()
        self._store = hs.get_datastore()
        self.auth = hs.get_auth()
        self._server_notice_content = hs.config.user_consent_server_notice_content
        self._admin_uri = hs.config.admin_uri
        self._limit_usage_by_mau = hs.config.limit_usage_by_mau
        self._hs_disabled = hs.config.hs_disabled

        self._resouce_limited = False
        self._message_handler = hs.get_message_handler()
        self._state = hs.get_state_handler()
        # Config checks?

    @defer.inlineCallbacks
    def maybe_send_server_notice_to_user(self, user_id):
        """Check if we need to send a notice to this user, and does so if so

        Args:
            user_id (str): user to check

        Returns:
            Deferred
        """
        if self._hs_disabled is True:
            return

        if self._limit_usage_by_mau is False:
            return

        timestamp = yield self._store.user_last_seen_monthly_active(user_id)
        if timestamp is None:
            # This user will be blocked from receiving the notice anyway.
            # In practice, not sure we can ever get here
            return

        # Determine current state of room

        room_id = yield self._server_notices_manager.get_notice_room_for_user(user_id)

        yield self._check_and_set_tags(user_id, room_id)
        currently_blocked, ref_events = yield self._is_room_currently_blocked(room_id)

        try:
            # Normally should always pass in user_id if you have it, but in
            # this case are checking what would happen to other users if they
            # were to arrive.
            yield self.auth.check_auth_blocking()
            if currently_blocked:
                # Room is notifying of a block, when it ought not to be.
                # Remove block notification
                content = {
                    "pinned": ref_events
                }
                yield self._server_notices_manager.send_notice(
                    user_id, content, EventTypes.Pinned, '',
                )

        except AuthError as e:

            try:
                if not currently_blocked:
                    # Room is not notifying of a block, when it ought to be.
                    # Add block notification
                    content = {
                        'body': e.msg,
                        'admin_uri': self._admin_uri,
                    }
                    event = yield self._server_notices_manager.send_notice(
                        user_id, content, EventTypes.ServerNoticeLimitReached
                    )

                    content = {
                        "pinned": [
                            event.event_id,
                        ]
                    }
                    yield self._server_notices_manager.send_notice(
                        user_id, content, EventTypes.Pinned, '',
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
        tags = yield self._store.get_tags_for_user(user_id)
        server_notices_tags = tags.get(room_id)
        need_to_set_tag = True
        if server_notices_tags:
            if server_notice_tags.get(SERVER_NOTICE_ROOM_TAG):
                # tag already present, nothing to do here
                need_to_set_tag = False
        if need_to_set_tag:
            yield self._store.add_tag_to_room(
                user_id, room_id, SERVER_NOTICE_ROOM_TAG, None
            )

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
        except AuthError as e:
            # The user has yet to join the server notices room
            pass

        referenced_events = []
        if pinned_state_event is not None:
            referenced_events = pinned_state_event.content.get('pinned')

        events = yield self._store.get_events(referenced_events)
        event_to_remove = None
        for event_id, event in events.items():
            if event.type == EventTypes.ServerNoticeLimitReached:
                currently_blocked = True
                # remove event in case we need to disable blocking later on.
                if event_id in referenced_events:
                    referenced_events.remove(event.event_id)

        defer.returnValue((currently_blocked, referenced_events))
