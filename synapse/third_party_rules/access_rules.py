# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
import email.utils
import logging
from typing import Dict, List, Optional, Tuple

from twisted.internet import defer

from synapse.api.constants import EventTypes, JoinRules, Membership, RoomCreationPreset
from synapse.api.errors import SynapseError
from synapse.config._base import ConfigError
from synapse.events import EventBase
from synapse.module_api import ModuleApi
from synapse.types import Requester, StateMap, UserID, get_domain_from_id

logger = logging.getLogger(__name__)

ACCESS_RULES_TYPE = "im.vector.room.access_rules"


class AccessRules:
    DIRECT = "direct"
    RESTRICTED = "restricted"
    UNRESTRICTED = "unrestricted"


VALID_ACCESS_RULES = (
    AccessRules.DIRECT,
    AccessRules.RESTRICTED,
    AccessRules.UNRESTRICTED,
)

# Rules to which we need to apply the power levels restrictions.
#
# These are all of the rules that neither:
#  * forbid users from joining based on a server blacklist (which means that there
#     is no need to apply power level restrictions), nor
#  * target direct chats (since we allow both users to be room admins in this case).
#
# The power-level restrictions, when they are applied, prevent the following:
#  * the default power level for users (users_default) being set to anything other than 0.
#  * a non-default power level being assigned to any user which would be forbidden from
#     joining a restricted room.
RULES_WITH_RESTRICTED_POWER_LEVELS = (AccessRules.UNRESTRICTED,)


class RoomAccessRules(object):
    """Implementation of the ThirdPartyEventRules module API that allows federation admins
    to define custom rules for specific events and actions.
    Implements the custom behaviour for the "im.vector.room.access_rules" state event.

    Takes a config in the format:

    third_party_event_rules:
        module: third_party_rules.RoomAccessRules
        config:
            # List of domains (server names) that can't be invited to rooms if the
            # "restricted" rule is set. Defaults to an empty list.
            domains_forbidden_when_restricted: []

            # Identity server to use when checking the HS an email address belongs to
            # using the /info endpoint. Required.
            id_server: "vector.im"

    Don't forget to consider if you can invite users from your own domain.
    """

    def __init__(
        self, config: Dict, module_api: ModuleApi,
    ):
        self.id_server = config["id_server"]
        self.module_api = module_api

        self.domains_forbidden_when_restricted = config.get(
            "domains_forbidden_when_restricted", []
        )

    @staticmethod
    def parse_config(config: Dict) -> Dict:
        """Parses and validates the options specified in the homeserver config.

        Args:
            config: The config dict.

        Returns:
            The config dict.

        Raises:
            ConfigError: If there was an issue with the provided module configuration.
        """
        if "id_server" not in config:
            raise ConfigError("No IS for event rules TchapEventRules")

        return config

    async def on_create_room(
        self, requester: Requester, config: Dict, is_requester_admin: bool,
    ) -> bool:
        """Implements synapse.events.ThirdPartyEventRules.on_create_room.

        Checks if a im.vector.room.access_rules event is being set during room creation.
        If yes, make sure the event is correct. Otherwise, append an event with the
        default rule to the initial state.

        Checks if a m.rooms.power_levels event is being set during room creation.
        If yes, make sure the event is allowed. Otherwise, set power_level_content_override
        in the config dict to our modified version of the default room power levels.

        Args:
            requester: The user who is making the createRoom request.
            config: The createRoom config dict provided by the user.
            is_requester_admin: Whether the requester is a Synapse admin.

        Returns:
            Whether the request is allowed.

        Raises:
            SynapseError: If the createRoom config dict is invalid or its contents blocked.
        """
        is_direct = config.get("is_direct")
        preset = config.get("preset")
        access_rule = None
        join_rule = None

        # If there's a rules event in the initial state, check if it complies with the
        # spec for im.vector.room.access_rules and deny the request if not.
        for event in config.get("initial_state", []):
            if event["type"] == ACCESS_RULES_TYPE:
                access_rule = event["content"].get("rule")

                # Make sure the event has a valid content.
                if access_rule is None:
                    raise SynapseError(400, "Invalid access rule")

                # Make sure the rule name is valid.
                if access_rule not in VALID_ACCESS_RULES:
                    raise SynapseError(400, "Invalid access rule")

                if (is_direct and access_rule != AccessRules.DIRECT) or (
                    access_rule == AccessRules.DIRECT and not is_direct
                ):
                    raise SynapseError(400, "Invalid access rule")

            if event["type"] == EventTypes.JoinRules:
                join_rule = event["content"].get("join_rule")

        if access_rule is None:
            # If there's no access rules event in the initial state, create one with the
            # default setting.
            if is_direct:
                default_rule = AccessRules.DIRECT
            else:
                # If the default value for non-direct chat changes, we should make another
                # case here for rooms created with either a "public" join_rule or the
                # "public_chat" preset to make sure those keep defaulting to "restricted"
                default_rule = AccessRules.RESTRICTED

            if not config.get("initial_state"):
                config["initial_state"] = []

            config["initial_state"].append(
                {
                    "type": ACCESS_RULES_TYPE,
                    "state_key": "",
                    "content": {"rule": default_rule},
                }
            )

            access_rule = default_rule

        # Check that the preset in use is compatible with the access rule, whether it's
        # user-defined or the default.
        #
        # Direct rooms may not have their join_rules set to JoinRules.PUBLIC.
        if (
            join_rule == JoinRules.PUBLIC or preset == RoomCreationPreset.PUBLIC_CHAT
        ) and access_rule == AccessRules.DIRECT:
            raise SynapseError(400, "Invalid access rule")

        # Check if the creator can override values for the power levels.
        allowed = self._is_power_level_content_allowed(
            config.get("power_level_content_override", {}), access_rule
        )
        if not allowed:
            raise SynapseError(400, "Invalid power levels content override")

        use_default_power_levels = True
        if config.get("power_level_content_override"):
            use_default_power_levels = False

        # Second loop for events we need to know the current rule to process.
        for event in config.get("initial_state", []):
            if event["type"] == EventTypes.PowerLevels:
                allowed = self._is_power_level_content_allowed(
                    event["content"], access_rule
                )
                if not allowed:
                    raise SynapseError(400, "Invalid power levels content")

                use_default_power_levels = False

        # If power levels were not overridden by the user, override with DINUM's preferred
        # defaults instead
        if use_default_power_levels:
            config["power_level_content_override"] = self._get_default_power_levels(
                requester.user.to_string()
            )

        return True

    # If power levels are not overridden by the user during room creation, the following
    # rules are used instead. Changes from Synapse's default power levels are noted.
    #
    # The same power levels are currently applied regardless of room preset.
    @staticmethod
    def _get_default_power_levels(user_id: str) -> Dict:
        return {
            "users": {user_id: 100},
            "users_default": 0,
            "events": {
                EventTypes.Name: 50,
                EventTypes.PowerLevels: 100,
                EventTypes.RoomHistoryVisibility: 100,
                EventTypes.CanonicalAlias: 50,
                EventTypes.RoomAvatar: 50,
                EventTypes.Tombstone: 100,
                EventTypes.ServerACL: 100,
                EventTypes.RoomEncryption: 100,
            },
            "events_default": 0,
            "state_default": 100,  # Admins should be the only ones to perform other tasks
            "ban": 50,
            "kick": 50,
            "redact": 50,
            "invite": 50,  # All rooms should require mod to invite, even private
        }

    @defer.inlineCallbacks
    def check_threepid_can_be_invited(
        self, medium: str, address: str, state_events: StateMap[EventBase],
    ) -> bool:
        """Implements synapse.events.ThirdPartyEventRules.check_threepid_can_be_invited.

        Check if a threepid can be invited to the room via a 3PID invite given the current
        rules and the threepid's address, by retrieving the HS it's mapped to from the
        configured identity server, and checking if we can invite users from it.

        Args:
            medium: The medium of the threepid.
            address: The address of the threepid.
            state_events: A dict mapping (event type, state key) to state event.
                State events in the room the threepid is being invited to.

        Returns:
            Whether the threepid invite is allowed.
        """
        rule = self._get_rule_from_state(state_events)

        if medium != "email":
            return False

        if rule != AccessRules.RESTRICTED:
            # Only "restricted" requires filtering 3PID invites. We don't need to do
            # anything for "direct" here, because only "restricted" requires filtering
            # based on the HS the address is mapped to.
            return True

        parsed_address = email.utils.parseaddr(address)[1]
        if parsed_address != address:
            # Avoid reproducing the security issue described here:
            # https://matrix.org/blog/2019/04/18/security-update-sydent-1-0-2
            # It's probably not worth it but let's just be overly safe here.
            return False

        # Get the HS this address belongs to from the identity server.
        res = yield self.module_api.http_client.get_json(
            "https://%s/_matrix/identity/api/v1/info" % (self.id_server,),
            {"medium": medium, "address": address},
        )

        # Look for a domain that's not forbidden from being invited.
        if not res.get("hs"):
            return False
        if res.get("hs") in self.domains_forbidden_when_restricted:
            return False

        return True

    async def check_event_allowed(
        self, event: EventBase, state_events: StateMap[EventBase],
    ) -> bool:
        """Implements synapse.events.ThirdPartyEventRules.check_event_allowed.

        Checks the event's type and the current rule and calls the right function to
        determine whether the event can be allowed.

        Args:
            event: The event to check.
            state_events: A dict mapping (event type, state key) to state event.
                State events in the room the event originated from.

        Returns:
            True if the event can be allowed, False otherwise.
        """
        if event.type == ACCESS_RULES_TYPE:
            return await self._on_rules_change(event, state_events)

        # We need to know the rule to apply when processing the event types below.
        rule = self._get_rule_from_state(state_events)

        if event.type == EventTypes.PowerLevels:
            return self._is_power_level_content_allowed(
                event.content, rule, on_room_creation=False
            )

        if event.type == EventTypes.Member or event.type == EventTypes.ThirdPartyInvite:
            return await self._on_membership_or_invite(event, rule, state_events)

        if event.type == EventTypes.JoinRules:
            return self._on_join_rule_change(event, rule)

        if event.type == EventTypes.RoomAvatar:
            return self._on_room_avatar_change(event, rule)

        if event.type == EventTypes.Name:
            return self._on_room_name_change(event, rule)

        if event.type == EventTypes.Topic:
            return self._on_room_topic_change(event, rule)

        return True

    async def check_visibility_can_be_modified(
        self, room_id: str, state_events: StateMap[EventBase], new_visibility: str
    ) -> bool:
        """Implements
        synapse.events.ThirdPartyEventRules.check_visibility_can_be_modified

        Determines whether a room can be published, or removed from, the public room
        list. A room is published if its visibility is set to "public". Otherwise,
        its visibility is "private". A room with access rule other than "restricted"
        may not be published.

        Args:
            room_id: The ID of the room.
            state_events: A dict mapping (event type, state key) to state event.
                State events in the room.
            new_visibility: The new visibility state. Either "public" or "private".

        Returns:
            Whether the room is allowed to be published to, or removed from, the public
            rooms directory.
        """
        # We need to know the rule to apply when processing the event types below.
        rule = self._get_rule_from_state(state_events)

        # Allow adding a room to the public rooms list only if it is restricted
        if new_visibility == "public":
            return rule == AccessRules.RESTRICTED

        # By default a room is created as "restricted", meaning it is allowed to be
        # published to the public rooms directory.
        return True

    async def _on_rules_change(
        self, event: EventBase, state_events: StateMap[EventBase]
    ):
        """Checks whether an im.vector.room.access_rules event is forbidden or allowed.

        Args:
            event: The im.vector.room.access_rules event.
            state_events: A dict mapping (event type, state key) to state event.
                State events in the room before the event was sent.
        Returns:
            True if the event can be allowed, False otherwise.
        """
        new_rule = event.content.get("rule")

        # Check for invalid values.
        if new_rule not in VALID_ACCESS_RULES:
            return False

        # Make sure we don't apply "direct" if the room has more than two members.
        if new_rule == AccessRules.DIRECT:
            existing_members, threepid_tokens = self._get_members_and_tokens_from_state(
                state_events
            )

            if len(existing_members) > 2 or len(threepid_tokens) > 1:
                return False

        if new_rule != AccessRules.RESTRICTED:
            # Block this change if this room is currently listed in the public rooms
            # directory
            if await self.module_api.public_room_list_manager.room_is_in_public_room_list(
                event.room_id
            ):
                return False

        prev_rules_event = state_events.get((ACCESS_RULES_TYPE, ""))

        # Now that we know the new rule doesn't break the "direct" case, we can allow any
        # new rule in rooms that had none before.
        if prev_rules_event is None:
            return True

        prev_rule = prev_rules_event.content.get("rule")

        # Currently, we can only go from "restricted" to "unrestricted".
        return (
            prev_rule == AccessRules.RESTRICTED and new_rule == AccessRules.UNRESTRICTED
        )

    async def _on_membership_or_invite(
        self, event: EventBase, rule: str, state_events: StateMap[EventBase],
    ) -> bool:
        """Applies the correct rule for incoming m.room.member and
        m.room.third_party_invite events.

        Args:
            event: The event to check.
            rule: The name of the rule to apply.
            state_events: A dict mapping (event type, state key) to state event.
                The state of the room before the event was sent.

        Returns:
            True if the event can be allowed, False otherwise.
        """
        if rule == AccessRules.RESTRICTED:
            ret = self._on_membership_or_invite_restricted(event)
        elif rule == AccessRules.UNRESTRICTED:
            ret = self._on_membership_or_invite_unrestricted(event, state_events)
        elif rule == AccessRules.DIRECT:
            ret = self._on_membership_or_invite_direct(event, state_events)
        else:
            # We currently apply the default (restricted) if we don't know the rule, we
            # might want to change that in the future.
            ret = self._on_membership_or_invite_restricted(event)

        if event.type == "m.room.member":
            # If this is an admin leaving, and they are the last admin in the room,
            # raise the power levels of the room so that the room is 'frozen'.
            #
            # We have to freeze the room by puppeting an admin user, which we can
            # only do for local users
            if (
                self._is_local_user(event.sender)
                and event.membership == Membership.LEAVE
            ):
                await self._freeze_room_if_last_admin_is_leaving(event, state_events)

        return ret

    async def _freeze_room_if_last_admin_is_leaving(
        self, event: EventBase, state_events: StateMap[EventBase]
    ):
        power_level_state_event = state_events.get(
            (EventTypes.PowerLevels, "")
        )  # type: EventBase
        if not power_level_state_event:
            return
        power_level_content = power_level_state_event.content

        # Do some validation checks on the power level state event
        if (
            not isinstance(power_level_content, dict)
            or "users" not in power_level_content
            or not isinstance(power_level_content["users"], dict)
        ):
            # We can't use this power level event to determine whether the room should be
            # frozen. Bail out.
            return

        user_id = event.get("sender")
        if not user_id:
            return

        # Get every admin user defined in the room's state
        admin_users = {
            user
            for user, power_level in power_level_content["users"].items()
            if power_level >= 100
        }

        if user_id not in admin_users:
            # This user is not an admin, ignore them
            return

        if any(
            event_type == EventTypes.Member
            and event.membership in [Membership.JOIN, Membership.INVITE]
            and state_key in admin_users
            and state_key != user_id
            for (event_type, state_key), event in state_events.items()
        ):
            # There's another admin user in, or invited to, the room
            return

        # Freeze the room by raising the required power level to send events to 100
        logger.info("Freezing room '%s'", event.room_id)

        # Modify the existing power levels to raise all required types to 100
        #
        # This changes a power level state event's content from something like:
        # {
        #     "redact": 50,
        #     "state_default": 50,
        #     "ban": 50,
        #     "notifications": {
        #         "room": 50
        #     },
        #     "events": {
        #         "m.room.avatar": 50,
        #         "m.room.encryption": 50,
        #         "m.room.canonical_alias": 50,
        #         "m.room.name": 50,
        #         "im.vector.modular.widgets": 50,
        #         "m.room.topic": 50,
        #         "m.room.tombstone": 50,
        #         "m.room.history_visibility": 100,
        #         "m.room.power_levels": 100
        #     },
        #     "users_default": 0,
        #     "events_default": 0,
        #     "users": {
        #         "@admin:example.com": 100,
        #     },
        #     "kick": 50,
        #     "invite": 0
        # }
        #
        # to
        #
        # {
        #     "redact": 100,
        #     "state_default": 100,
        #     "ban": 100,
        #     "notifications": {
        #         "room": 50
        #     },
        #     "events": {}
        #     "users_default": 0,
        #     "events_default": 100,
        #     "users": {
        #         "@admin:example.com": 100,
        #     },
        #     "kick": 100,
        #     "invite": 100
        # }
        new_content = {}
        for key, value in power_level_content.items():
            # Do not change "users_default", as that key specifies the default power
            # level of new users
            if isinstance(value, int) and key != "users_default":
                value = 100
            new_content[key] = value

        # Set some values in case they are missing from the original
        # power levels event content
        new_content.update(
            {
                # Clear out any special-cased event keys
                "events": {},
                # Ensure state_default and events_default keys exist and are 100.
                # Otherwise a lower PL user could potentially send state events that
                # aren't explicitly mentioned elsewhere in the power level dict
                "state_default": 100,
                "events_default": 100,
                # Membership events default to 50 if they aren't present. Set them
                # to 100 here, as they would be set to 100 if they were present anyways
                "ban": 100,
                "kick": 100,
                "invite": 100,
                "redact": 100,
            }
        )

        await self.module_api.create_and_send_event_into_room(
            {
                "room_id": event.room_id,
                "sender": user_id,
                "type": EventTypes.PowerLevels,
                "content": new_content,
                "state_key": "",
            }
        )

    def _on_membership_or_invite_restricted(self, event: EventBase) -> bool:
        """Implements the checks and behaviour specified for the "restricted" rule.

        "restricted" currently means that users can only invite users if their server is
        included in a limited list of domains.

        Args:
            event: The event to check.

        Returns:
            True if the event can be allowed, False otherwise.
        """
        # We're not applying the rules on m.room.third_party_member events here because
        # the filtering on threepids is done in check_threepid_can_be_invited, which is
        # called before check_event_allowed.
        if event.type == EventTypes.ThirdPartyInvite:
            return True

        # We only need to process "join" and "invite" memberships, in order to be backward
        # compatible, e.g. if a user from a blacklisted server joined a restricted room
        # before the rules started being enforced on the server, that user must be able to
        # leave it.
        if event.membership not in [Membership.JOIN, Membership.INVITE]:
            return True

        invitee_domain = get_domain_from_id(event.state_key)
        return invitee_domain not in self.domains_forbidden_when_restricted

    def _on_membership_or_invite_unrestricted(
        self, event: EventBase, state_events: StateMap[EventBase]
    ) -> bool:
        """Implements the checks and behaviour specified for the "unrestricted" rule.

        "unrestricted" currently means that forbidden users cannot join without an invite.

        Returns:
            True if the event can be allowed, False otherwise.
        """
        # If this is a join from a forbidden user and they don't have an invite to the
        # room, then deny it
        if event.type == EventTypes.Member and event.membership == Membership.JOIN:
            # Check if this user is from a forbidden server
            target_domain = get_domain_from_id(event.state_key)
            if target_domain in self.domains_forbidden_when_restricted:
                # If so, they'll need an invite to join this room. Check if one exists
                if not self._user_is_invited_to_room(event.state_key, state_events):
                    return False

        return True

    def _on_membership_or_invite_direct(
        self, event: EventBase, state_events: StateMap[EventBase],
    ) -> bool:
        """Implements the checks and behaviour specified for the "direct" rule.

        "direct" currently means that no member is allowed apart from the two initial
        members the room was created for (i.e. the room's creator and their first invitee).

        Args:
            event: The event to check.
            state_events: A dict mapping (event type, state key) to state event.
                The state of the room before the event was sent.

        Returns:
            True if the event can be allowed, False otherwise.
        """
        # Get the room memberships and 3PID invite tokens from the room's state.
        existing_members, threepid_tokens = self._get_members_and_tokens_from_state(
            state_events
        )

        # There should never be more than one 3PID invite in the room state: if the second
        # original user came and left, and we're inviting them using their email address,
        # given we know they have a Matrix account binded to the address (so they could
        # join the first time), Synapse will successfully look it up before attempting to
        # store an invite on the IS.
        if len(threepid_tokens) == 1 and event.type == EventTypes.ThirdPartyInvite:
            # If we already have a 3PID invite in flight, don't accept another one, unless
            # the new one has the same invite token as its state key. This is because 3PID
            # invite revocations must be allowed, and a revocation is basically a new 3PID
            # invite event with an empty content and the same token as the invite it
            # revokes.
            return event.state_key in threepid_tokens

        if len(existing_members) == 2:
            # If the user was within the two initial user of the room, Synapse would have
            # looked it up successfully and thus sent a m.room.member here instead of
            # m.room.third_party_invite.
            if event.type == EventTypes.ThirdPartyInvite:
                return False

            # We can only have m.room.member events here. The rule in this case is to only
            # allow the event if its target is one of the initial two members in the room,
            # i.e. the state key of one of the two m.room.member states in the room.
            return event.state_key in existing_members

        # We're alone in the room (and always have been) and there's one 3PID invite in
        # flight.
        if len(existing_members) == 1 and len(threepid_tokens) == 1:
            # We can only have m.room.member events here. In this case, we can only allow
            # the event if it's either a m.room.member from the joined user (we can assume
            # that the only m.room.member event is a join otherwise we wouldn't be able to
            # send an event to the room) or an an invite event which target is the invited
            # user.
            target = event.state_key
            is_from_threepid_invite = self._is_invite_from_threepid(
                event, threepid_tokens[0]
            )
            return is_from_threepid_invite or target == existing_members[0]

        return True

    def _is_power_level_content_allowed(
        self, content: Dict, access_rule: str, on_room_creation: bool = True
    ) -> bool:
        """Check if a given power levels event is permitted under the given access rule.

        It shouldn't be allowed if it either changes the default PL to a non-0 value or
        gives a non-0 PL to a user that would have been forbidden from joining the room
        under a more restrictive access rule.

        Args:
            content: The content of the m.room.power_levels event to check.
            access_rule: The access rule in place in this room.
            on_room_creation: True if this call is happening during a room's
                creation, False otherwise.

        Returns:
            Whether the content of the power levels event is valid.
        """
        # Only enforce these rules during room creation
        #
        # We want to allow admins to modify or fix the power levels in a room if they
        # have a special circumstance, but still want to encourage a certain pattern during
        # room creation.
        if on_room_creation:
            # If invite requirements are <PL50
            if content.get("invite", 50) < 50:
                return False

            # If "other" state requirements are <PL100
            if content.get("state_default", 100) < 100:
                return False

        # Check if we need to apply the restrictions with the current rule.
        if access_rule not in RULES_WITH_RESTRICTED_POWER_LEVELS:
            return True

        # If users_default is explicitly set to a non-0 value, deny the event.
        users_default = content.get("users_default", 0)
        if users_default:
            return False

        users = content.get("users", {})
        for user_id, power_level in users.items():
            server_name = get_domain_from_id(user_id)
            # Check the domain against the blacklist. If found, and the PL isn't 0, deny
            # the event.
            if (
                server_name in self.domains_forbidden_when_restricted
                and power_level != 0
            ):
                return False

        return True

    def _on_join_rule_change(self, event: EventBase, rule: str) -> bool:
        """Check whether a join rule change is allowed.

        A join rule change is always allowed unless the new join rule is "public" and
        the current access rule is "direct".

        Args:
            event: The event to check.
            rule: The name of the rule to apply.

        Returns:
            Whether the change is allowed.
        """
        if event.content.get("join_rule") == JoinRules.PUBLIC:
            return rule != AccessRules.DIRECT

        return True

    def _on_room_avatar_change(self, event: EventBase, rule: str) -> bool:
        """Check whether a change of room avatar is allowed.
        The current rule is to forbid such a change in direct chats but allow it
        everywhere else.

        Args:
            event: The event to check.
            rule: The name of the rule to apply.

        Returns:
            True if the event can be allowed, False otherwise.
        """
        return rule != AccessRules.DIRECT

    def _on_room_name_change(self, event: EventBase, rule: str) -> bool:
        """Check whether a change of room name is allowed.
        The current rule is to forbid such a change in direct chats but allow it
        everywhere else.

        Args:
            event: The event to check.
            rule: The name of the rule to apply.

        Returns:
            True if the event can be allowed, False otherwise.
        """
        return rule != AccessRules.DIRECT

    def _on_room_topic_change(self, event: EventBase, rule: str) -> bool:
        """Check whether a change of room topic is allowed.
        The current rule is to forbid such a change in direct chats but allow it
        everywhere else.

        Args:
            event: The event to check.
            rule: The name of the rule to apply.

        Returns:
            True if the event can be allowed, False otherwise.
        """
        return rule != AccessRules.DIRECT

    @staticmethod
    def _get_rule_from_state(state_events: StateMap[EventBase]) -> Optional[str]:
        """Extract the rule to be applied from the given set of state events.

        Args:
            state_events: A dict mapping (event type, state key) to state event.

        Returns:
            The name of the rule (either "direct", "restricted" or "unrestricted") if found,
                else None.
        """
        access_rules = state_events.get((ACCESS_RULES_TYPE, ""))
        if access_rules is None:
            return AccessRules.RESTRICTED

        return access_rules.content.get("rule")

    @staticmethod
    def _get_join_rule_from_state(state_events: StateMap[EventBase]) -> Optional[str]:
        """Extract the room's join rule from the given set of state events.

        Args:
            state_events (dict[tuple[event type, state key], EventBase]): The set of state
                events.

        Returns:
            The name of the join rule (either "public", or "invite") if found, else None.
        """
        join_rule_event = state_events.get((EventTypes.JoinRules, ""))
        if join_rule_event is None:
            return None

        return join_rule_event.content.get("join_rule")

    @staticmethod
    def _get_members_and_tokens_from_state(
        state_events: StateMap[EventBase],
    ) -> Tuple[List[str], List[str]]:
        """Retrieves the list of users that have a m.room.member event in the room,
        as well as 3PID invites tokens in the room.

        Args:
            state_events: A dict mapping (event type, state key) to state event.

        Returns:
            A tuple containing the:
                * targets of the m.room.member events in the state.
                * 3PID invite tokens in the state.
        """
        existing_members = []
        threepid_invite_tokens = []
        for key, state_event in state_events.items():
            if key[0] == EventTypes.Member and state_event.content:
                existing_members.append(state_event.state_key)
            if key[0] == EventTypes.ThirdPartyInvite and state_event.content:
                # Don't include revoked invites.
                threepid_invite_tokens.append(state_event.state_key)

        return existing_members, threepid_invite_tokens

    @staticmethod
    def _is_invite_from_threepid(invite: EventBase, threepid_invite_token: str) -> bool:
        """Checks whether the given invite follows the given 3PID invite.

        Args:
             invite: The m.room.member event with "invite" membership.
             threepid_invite_token: The state key from the 3PID invite.

        Returns:
            Whether the invite is due to the given 3PID invite.
        """
        token = (
            invite.content.get("third_party_invite", {})
            .get("signed", {})
            .get("token", "")
        )

        return token == threepid_invite_token

    def _is_local_user(self, user_id: str) -> bool:
        """Checks whether a given user ID belongs to this homeserver, or a remote

        Args:
            user_id: A user ID to check.

        Returns:
            True if the user belongs to this homeserver, False otherwise.
        """
        user = UserID.from_string(user_id)

        # Extract the localpart and ask the module API for a user ID from the localpart
        # The module API will append the local homeserver's server_name
        local_user_id = self.module_api.get_qualified_user_id(user.localpart)

        # If the user ID we get based on the localpart is the same as the original user ID,
        # then they were a local user
        return user_id == local_user_id

    def _user_is_invited_to_room(
        self, user_id: str, state_events: StateMap[EventBase]
    ) -> bool:
        """Checks whether a given user has been invited to a room

        A user has an invite for a room if its state contains a `m.room.member`
        event with membership "invite" and their user ID as the state key.

        Args:
            user_id: The user to check.
            state_events: The state events from the room.

        Returns:
            True if the user has been invited to the room, or False if they haven't.
        """
        for (event_type, state_key), state_event in state_events.items():
            if (
                event_type == EventTypes.Member
                and state_key == user_id
                and state_event.membership == Membership.INVITE
            ):
                return True

        return False
