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
from typing import TYPE_CHECKING, Optional

from synapse.api.constants import EventTypes, Membership, RoomCreationPreset
from synapse.events import EventBase
from synapse.types import Requester, StreamKeyType, UserID, create_requester
from synapse.util.caches.descriptors import cached

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

SERVER_NOTICE_ROOM_TAG = "m.server_notice"


class ServerNoticesManager:
    def __init__(self, hs: "HomeServer"):
        self._store = hs.get_datastores().main
        self._config = hs.config
        self._account_data_handler = hs.get_account_data_handler()
        self._room_creation_handler = hs.get_room_creation_handler()
        self._room_member_handler = hs.get_room_member_handler()
        self._event_creation_handler = hs.get_event_creation_handler()
        self._message_handler = hs.get_message_handler()
        self._is_mine_id = hs.is_mine_id
        self._server_name = hs.hostname

        self._notifier = hs.get_notifier()
        self.server_notices_mxid = self._config.servernotices.server_notices_mxid

    def is_enabled(self) -> bool:
        """Checks if server notices are enabled on this server."""
        return self.server_notices_mxid is not None

    async def send_notice(
        self,
        user_id: str,
        event_content: dict,
        type: str = EventTypes.Message,
        state_key: Optional[str] = None,
        txn_id: Optional[str] = None,
    ) -> EventBase:
        """Send a notice to the given user

        Creates the server notices room, if none exists.

        Args:
            user_id: mxid of user to send event to.
            event_content: content of event to send
            type: type of event
            is_state_event: Is the event a state event
            txn_id: The transaction ID.
        """
        room_id = await self.get_or_create_notice_room_for_user(user_id)
        await self.maybe_invite_user_to_room(user_id, room_id)

        assert self.server_notices_mxid is not None
        requester = create_requester(
            self.server_notices_mxid, authenticated_entity=self._server_name
        )

        logger.info("Sending server notice to %s", user_id)

        event_dict = {
            "type": type,
            "room_id": room_id,
            "sender": self.server_notices_mxid,
            "content": event_content,
        }

        if state_key is not None:
            event_dict["state_key"] = state_key

        event, _ = await self._event_creation_handler.create_and_send_nonmember_event(
            requester, event_dict, ratelimit=False, txn_id=txn_id
        )
        return event

    @cached()
    async def maybe_get_notice_room_for_user(self, user_id: str) -> Optional[str]:
        """Try to look up the server notice room for this user if it exists.

        Does not create one if none can be found.

        Args:
            user_id: the user we want a server notice room for.

        Returns:
            The room's ID, or None if no room could be found.
        """
        # If there is no server notices MXID, then there is no server notices room
        if self.server_notices_mxid is None:
            return None

        rooms = await self._store.get_rooms_for_local_user_where_membership_is(
            user_id, [Membership.INVITE, Membership.JOIN]
        )
        for room in rooms:
            # it's worth noting that there is an asymmetry here in that we
            # expect the user to be invited or joined, but the system user must
            # be joined. This is kinda deliberate, in that if somebody somehow
            # manages to invite the system user to a room, that doesn't make it
            # the server notices room.
            is_server_notices_room = await self._store.check_local_user_in_room(
                user_id=self.server_notices_mxid, room_id=room.room_id
            )
            if is_server_notices_room:
                # we found a room which our user shares with the system notice
                # user
                return room.room_id

        return None

    @cached()
    async def get_or_create_notice_room_for_user(self, user_id: str) -> str:
        """Get the room for notices for a given user

        If we have not yet created a notice room for this user, create it, but don't
        invite the user to it.

        Args:
            user_id: complete user id for the user we want a room for

        Returns:
            room id of notice room.
        """
        if self.server_notices_mxid is None:
            raise Exception("Server notices not enabled")

        assert self._is_mine_id(user_id), "Cannot send server notices to remote users"

        requester = create_requester(
            self.server_notices_mxid, authenticated_entity=self._server_name
        )

        room_id = await self.maybe_get_notice_room_for_user(user_id)
        if room_id is not None:
            logger.info(
                "Using existing server notices room %s for user %s",
                room_id,
                user_id,
            )
            await self._update_notice_user_profile_if_changed(
                requester,
                room_id,
                self._config.servernotices.server_notices_mxid_display_name,
                self._config.servernotices.server_notices_mxid_avatar_url,
            )
            return room_id

        # apparently no existing notice room: create a new one
        logger.info("Creating server notices room for %s", user_id)

        # see if we want to override the profile info for the server user.
        # note that if we want to override either the display name or the
        # avatar, we have to use both.
        join_profile = None
        if (
            self._config.servernotices.server_notices_mxid_display_name is not None
            or self._config.servernotices.server_notices_mxid_avatar_url is not None
        ):
            join_profile = {
                "displayname": self._config.servernotices.server_notices_mxid_display_name,
                "avatar_url": self._config.servernotices.server_notices_mxid_avatar_url,
            }

        info, _ = await self._room_creation_handler.create_room(
            requester,
            config={
                "preset": RoomCreationPreset.PRIVATE_CHAT,
                "name": self._config.servernotices.server_notices_room_name,
                "power_level_content_override": {"users_default": -10},
            },
            ratelimit=False,
            creator_join_profile=join_profile,
        )
        room_id = info["room_id"]

        self.maybe_get_notice_room_for_user.invalidate((user_id,))

        max_id = await self._account_data_handler.add_tag_to_room(
            user_id, room_id, SERVER_NOTICE_ROOM_TAG, {}
        )
        self._notifier.on_new_event(StreamKeyType.ACCOUNT_DATA, max_id, users=[user_id])

        logger.info("Created server notices room %s for %s", room_id, user_id)
        return room_id

    async def maybe_invite_user_to_room(self, user_id: str, room_id: str) -> None:
        """Invite the given user to the given server room, unless the user has already
        joined or been invited to it.

        Args:
            user_id: The ID of the user to invite.
            room_id: The ID of the room to invite the user to.
        """
        assert self.server_notices_mxid is not None
        requester = create_requester(
            self.server_notices_mxid, authenticated_entity=self._server_name
        )

        # Check whether the user has already joined or been invited to this room. If
        # that's the case, there is no need to re-invite them.
        joined_rooms = await self._store.get_rooms_for_local_user_where_membership_is(
            user_id, [Membership.INVITE, Membership.JOIN]
        )
        for room in joined_rooms:
            if room.room_id == room_id:
                return

        await self._room_member_handler.update_membership(
            requester=requester,
            target=UserID.from_string(user_id),
            room_id=room_id,
            action="invite",
        )

    async def _update_notice_user_profile_if_changed(
        self,
        requester: Requester,
        room_id: str,
        display_name: Optional[str],
        avatar_url: Optional[str],
    ) -> None:
        """
        Updates the notice user's profile if it's different from what is in the room.

        Args:
            requester: The user who is performing the update.
            room_id: The ID of the server notice room
            display_name: The displayname of the server notice user
            avatar_url: The avatar url of the server notice user
        """
        logger.debug("Checking whether notice user profile has changed for %s", room_id)

        assert self.server_notices_mxid is not None

        notice_user_data_in_room = await self._message_handler.get_room_data(
            create_requester(self.server_notices_mxid),
            room_id,
            EventTypes.Member,
            self.server_notices_mxid,
        )

        assert notice_user_data_in_room is not None

        notice_user_profile_changed = (
            display_name != notice_user_data_in_room.content.get("displayname")
            or avatar_url != notice_user_data_in_room.content.get("avatar_url")
        )
        if notice_user_profile_changed:
            logger.info("Updating notice user profile in room %s", room_id)
            await self._room_member_handler.update_membership(
                requester=requester,
                target=UserID.from_string(self.server_notices_mxid),
                room_id=room_id,
                action="join",
                content={"displayname": display_name, "avatar_url": avatar_url},
            )
