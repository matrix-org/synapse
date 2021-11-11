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
from typing import Optional

from synapse.api.constants import EventTypes, Membership
from synapse.config._base import ConfigError
from synapse.module_api import ModuleApi

logger = logging.getLogger(__name__)


class DomainRuleChecker(object):
    """
    A re-implementation of the SpamChecker that prevents users in one domain from
    inviting users in other domains to rooms, based on a configuration.

    Takes a config in the format:

    spam_checker:
        module: "rulecheck.DomainRuleChecker"
        config:
          domain_mapping:
            "inviter_domain": [ "invitee_domain_permitted", "other_domain_permitted" ]
            "other_inviter_domain": [ "invitee_domain_permitted" ]
          default: False

          # Only let local users join rooms if they were explicitly invited.
          can_only_join_rooms_with_invite: false

          # Only let local users create rooms if they are inviting only one
          # other user, and that user matches the rules above.
          can_only_create_one_to_one_rooms: false

          # Only let local users invite during room creation, regardless of the
          # domain mapping rules above.
          can_only_invite_during_room_creation: false

          # Prevent local users from inviting users from certain domains to
          # rooms published in the room directory.
          domains_prevented_from_being_invited_to_published_rooms: []

          # Allow third party invites
          can_invite_by_third_party_id: true

    Don't forget to consider if you can invite users from your own domain.
    """

    def __init__(self, config, api: ModuleApi):
        self.domain_mapping = config["domain_mapping"] or {}
        self.default = config["default"]

        self.can_only_join_rooms_with_invite = config.get(
            "can_only_join_rooms_with_invite", False
        )
        self.can_only_invite_during_room_creation = config.get(
            "can_only_invite_during_room_creation", False
        )
        self.can_invite_by_third_party_id = config.get(
            "can_invite_by_third_party_id", True
        )
        self.domains_prevented_from_being_invited_to_published_rooms = config.get(
            "domains_prevented_from_being_invited_to_published_rooms", []
        )

        self._api = api

        self._api.register_spam_checker_callbacks(
            user_may_invite=self.user_may_invite,
            user_may_send_3pid_invite=self.user_may_send_3pid_invite,
            user_may_join_room=self.user_may_join_room,
        )

    async def _is_new_room(self, room_id: str) -> bool:
        """Checks if the room provided looks new according to its state.

        The module will consider a room to look new if the only m.room.member events in
        its state are either for the room's creator (i.e. its join event) or invites sent
        by the room's creator.

        Args:
            room_id: The ID of the room to check.

        Returns:
            Whether the room looks new.
        """
        state_event_filter = [
            (EventTypes.Create, None),
            (EventTypes.Member, None),
        ]

        events = await self._api.get_room_state(room_id, state_event_filter)

        room_creator = events[(EventTypes.Create, "")].sender

        for key, event in events.items():
            if key[0] == EventTypes.Create:
                continue

            if key[1] != room_creator:
                if (
                    event.sender != room_creator
                    and event.membership != Membership.INVITE
                ):
                    return False

        return True

    async def user_may_invite(
        self,
        inviter_userid: str,
        invitee_userid: str,
        room_id: str,
    ) -> bool:
        """Implements the user_may_invite spam checker callback."""
        return await self._user_may_invite(
            room_id=room_id,
            inviter_userid=inviter_userid,
            invitee_userid=invitee_userid,
        )

    async def user_may_send_3pid_invite(
        self,
        inviter_userid: str,
        medium: str,
        address: str,
        room_id: str,
    ) -> bool:
        """Implements the user_may_send_3pid_invite spam checker callback."""
        return await self._user_may_invite(
            room_id=room_id,
            inviter_userid=inviter_userid,
            invitee_userid=None,
        )

    async def _user_may_invite(
        self,
        room_id: str,
        inviter_userid: str,
        invitee_userid: Optional[str],
    ) -> bool:
        """Processes any incoming invite, both normal Matrix invites and 3PID ones, and
        check if they should be allowed.

        Args:
            room_id: The ID of the room the invite is happening in.
            inviter_userid: The MXID of the user sending the invite.
            invitee_userid: The MXID of the user being invited, or None if this is a 3PID
                invite (in which case no MXID exists for this user yet).

        Returns:
            Whether the invite can be allowed to go through.
        """
        new_room = await self._is_new_room(room_id)

        if self.can_only_invite_during_room_creation and not new_room:
            return False

        # If invitee_userid is None, then this means this is a 3PID invite (without a
        # bound MXID), so we allow it unless the configuration mandates blocking all 3PID
        # invites.
        if invitee_userid is None:
            return self.can_invite_by_third_party_id

        inviter_domain = self._get_domain_from_id(inviter_userid)
        invitee_domain = self._get_domain_from_id(invitee_userid)

        if inviter_domain not in self.domain_mapping:
            return self.default

        published_room = (
            await self._api.public_room_list_manager.room_is_in_public_room_list(
                room_id
            )
        )

        if (
            published_room
            and invitee_domain
            in self.domains_prevented_from_being_invited_to_published_rooms
        ):
            return False

        return invitee_domain in self.domain_mapping[inviter_domain]

    async def user_may_join_room(self, userid, room_id, is_invited):
        """Implements the user_may_join_room spam checker callback."""
        if self.can_only_join_rooms_with_invite and not is_invited:
            return False

        return True

    @staticmethod
    def parse_config(config):
        """Checks whether required fields exist in the provided configuration for the
        module.
        """
        if "default" in config:
            return config
        else:
            raise ConfigError("No default set for spam_config DomainRuleChecker")

    @staticmethod
    def _get_domain_from_id(mxid):
        """Parses a string and returns the domain part of the mxid.

        Args:
           mxid (str): a valid mxid

        Returns:
           str: the domain part of the mxid

        """
        idx = mxid.find(":")
        if idx == -1:
            raise Exception("Invalid ID: %r" % (mxid,))
        return mxid[idx + 1 :]
