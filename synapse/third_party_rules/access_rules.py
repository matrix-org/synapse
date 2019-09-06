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

from twisted.internet import defer

from synapse.api.constants import EventTypes, JoinRules, RoomCreationPreset
from synapse.api.errors import SynapseError
from synapse.config._base import ConfigError
from synapse.types import get_domain_from_id

ACCESS_RULES_TYPE = "im.vector.room.access_rules"
ACCESS_RULE_RESTRICTED = "restricted"
ACCESS_RULE_UNRESTRICTED = "unrestricted"
ACCESS_RULE_DIRECT = "direct"

VALID_ACCESS_RULES = (
    ACCESS_RULE_DIRECT,
    ACCESS_RULE_RESTRICTED,
    ACCESS_RULE_UNRESTRICTED,
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
RULES_WITH_RESTRICTED_POWER_LEVELS = (
    ACCESS_RULE_UNRESTRICTED,
)


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

    def __init__(self, config, http_client):
        self.http_client = http_client

        self.id_server = config["id_server"]

        self.domains_forbidden_when_restricted = config.get(
            "domains_forbidden_when_restricted", [],
        )

    @staticmethod
    def parse_config(config):
        if "id_server" in config:
            return config
        else:
            raise ConfigError("No IS for event rules TchapEventRules")

    def on_create_room(self, requester, config, is_requester_admin):
        """Implements synapse.events.ThirdPartyEventRules.on_create_room

        Checks if a im.vector.room.access_rules event is being set during room creation.
        If yes, make sure the event is correct. Otherwise, append an event with the
        default rule to the initial state.
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

                # Make sure the rule is "direct" if the room is a direct chat.
                if (
                    (is_direct and access_rule != ACCESS_RULE_DIRECT)
                    or (access_rule == ACCESS_RULE_DIRECT and not is_direct)
                ):
                    raise SynapseError(400, "Invalid access rule")

            if event["type"] == EventTypes.JoinRules:
                join_rule = event["content"].get("join_rule")

        if access_rule is None:
            # If there's no access rules event in the initial state, create one with the
            # default setting.
            if is_direct:
                default_rule = ACCESS_RULE_DIRECT
            else:
                # If the default value for non-direct chat changes, we should make another
                # case here for rooms created with either a "public" join_rule or the
                # "public_chat" preset to make sure those keep defaulting to "restricted"
                default_rule = ACCESS_RULE_RESTRICTED

            if not config.get("initial_state"):
                config["initial_state"] = []

            config["initial_state"].append({
                "type": ACCESS_RULES_TYPE,
                "state_key": "",
                "content": {
                    "rule": default_rule,
                }
            })

            access_rule = default_rule

        # Check that the preset or the join rule in use is compatible with the access
        # rule, whether it's a user-defined one or the default one (i.e. if it involves
        # a "public" join rule, the access rule must be "restricted").
        if (
            (
                join_rule == JoinRules.PUBLIC
                or preset == RoomCreationPreset.PUBLIC_CHAT
            ) and access_rule != ACCESS_RULE_RESTRICTED
        ):
            raise SynapseError(400, "Invalid access rule")

        # Check if the creator can override values for the power levels.
        allowed = self._is_power_level_content_allowed(
            config.get("power_level_content_override", {}), access_rule,
        )
        if not allowed:
            raise SynapseError(400, "Invalid power levels content override")

        # Second loop for events we need to know the current rule to process.
        for event in config.get("initial_state", []):
            if event["type"] == EventTypes.PowerLevels:
                allowed = self._is_power_level_content_allowed(
                    event["content"], access_rule
                )
                if not allowed:
                    raise SynapseError(400, "Invalid power levels content")

    @defer.inlineCallbacks
    def check_threepid_can_be_invited(self, medium, address, state_events):
        """Implements synapse.events.ThirdPartyEventRules.check_threepid_can_be_invited

        Check if a threepid can be invited to the room via a 3PID invite given the current
        rules and the threepid's address, by retrieving the HS it's mapped to from the
        configured identity server, and checking if we can invite users from it.
        """
        rule = self._get_rule_from_state(state_events)

        if medium != "email":
            defer.returnValue(False)

        if rule != ACCESS_RULE_RESTRICTED:
            # Only "restricted" requires filtering 3PID invites. We don't need to do
            # anything for "direct" here, because only "restricted" requires filtering
            # based on the HS the address is mapped to.
            defer.returnValue(True)

        parsed_address = email.utils.parseaddr(address)[1]
        if parsed_address != address:
            # Avoid reproducing the security issue described here:
            # https://matrix.org/blog/2019/04/18/security-update-sydent-1-0-2
            # It's probably not worth it but let's just be overly safe here.
            defer.returnValue(False)

        # Get the HS this address belongs to from the identity server.
        res = yield self.http_client.get_json(
            "https://%s/_matrix/identity/api/v1/info" % (self.id_server,),
            {
                "medium": medium,
                "address": address,
            }
        )

        # Look for a domain that's not forbidden from being invited.
        if not res.get("hs"):
            defer.returnValue(False)
        if res.get("hs") in self.domains_forbidden_when_restricted:
            defer.returnValue(False)

        defer.returnValue(True)

    def check_event_allowed(self, event, state_events):
        """Implements synapse.events.ThirdPartyEventRules.check_event_allowed

        Checks the event's type and the current rule and calls the right function to
        determine whether the event can be allowed.
        """
        if event.type == ACCESS_RULES_TYPE:
            return self._on_rules_change(event, state_events)

        # We need to know the rule to apply when processing the event types below.
        rule = self._get_rule_from_state(state_events)

        if event.type == EventTypes.PowerLevels:
            return self._is_power_level_content_allowed(event.content, rule)

        if event.type == EventTypes.Member or event.type == EventTypes.ThirdPartyInvite:
            return self._on_membership_or_invite(event, rule, state_events)

        if event.type == EventTypes.JoinRules:
            return self._on_join_rule_change(event, rule)

        if event.type == EventTypes.RoomAvatar:
            return self._on_room_avatar_change(event, rule)

        if event.type == EventTypes.Name:
            return self._on_room_name_change(event, rule)

        if event.type == EventTypes.Topic:
            return self._on_room_topic_change(event, rule)

        return True

    def _on_rules_change(self, event, state_events):
        """Implement the checks and behaviour specified on allowing or forbidding a new
        im.vector.room.access_rules event.

        Args:
            event (synapse.events.EventBase): The event to check.
            state_events (dict[tuple[event type, state key], EventBase]): The state of the
                room before the event was sent.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        new_rule = event.content.get("rule")

        # Check for invalid values.
        if new_rule not in VALID_ACCESS_RULES:
            return False

        # We must not allow rooms with the "public" join rule to be given any other access
        # rule than "restricted".
        join_rule = self._get_join_rule_from_state(state_events)
        if join_rule == JoinRules.PUBLIC and new_rule != ACCESS_RULE_RESTRICTED:
            return False

        # Make sure we don't apply "direct" if the room has more than two members.
        if new_rule == ACCESS_RULE_DIRECT:
            existing_members, threepid_tokens = self._get_members_and_tokens_from_state(
                state_events, event
            )

            if len(existing_members) > 2 or len(threepid_tokens) > 1:
                return False

        prev_rules_event = state_events.get((ACCESS_RULES_TYPE, ""))

        # Now that we know the new rule doesn't break the "direct" case, we can allow any
        # new rule in rooms that had none before.
        if prev_rules_event is None:
            return True

        prev_rule = prev_rules_event.content.get("rule")

        # Currently, we can only go from "restricted" to "unrestricted".
        if prev_rule == ACCESS_RULE_RESTRICTED and new_rule == ACCESS_RULE_UNRESTRICTED:
            return True

        return False

    def _on_membership_or_invite(self, event, rule, state_events):
        """Applies the correct rule for incoming m.room.member and
        m.room.third_party_invite events.

        Args:
            event (synapse.events.EventBase): The event to check.
            rule (str): The name of the rule to apply.
            state_events (dict[tuple[event type, state key], EventBase]): The state of the
                room before the event was sent.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        if rule == ACCESS_RULE_RESTRICTED:
            ret = self._on_membership_or_invite_restricted(event)
        elif rule == ACCESS_RULE_UNRESTRICTED:
            ret = self._on_membership_or_invite_unrestricted()
        elif rule == ACCESS_RULE_DIRECT:
            ret = self._on_membership_or_invite_direct(event, state_events)
        else:
            # We currently apply the default (restricted) if we don't know the rule, we
            # might want to change that in the future.
            ret = self._on_membership_or_invite_restricted(event)

        return ret

    def _on_membership_or_invite_restricted(self, event):
        """Implements the checks and behaviour specified for the "restricted" rule.

        "restricted" currently means that users can only invite users if their server is
        included in a limited list of domains.

        Args:
            event (synapse.events.EventBase): The event to check.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        # We're not applying the rules on m.room.third_party_member events here because
        # the filtering on threepids is done in check_threepid_can_be_invited, which is
        # called before check_event_allowed.
        if event.type == EventTypes.ThirdPartyInvite:
            return True
        invitee_domain = get_domain_from_id(event.state_key)
        return invitee_domain not in self.domains_forbidden_when_restricted

    def _on_membership_or_invite_unrestricted(self):
        """Implements the checks and behaviour specified for the "unrestricted" rule.

        "unrestricted" currently means that every event is allowed.

        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        return True

    def _on_membership_or_invite_direct(self, event, state_events):
        """Implements the checks and behaviour specified for the "direct" rule.

        "direct" currently means that no member is allowed apart from the two initial
        members the room was created for (i.e. the room's creator and their first
        invitee).

        Args:
            event (synapse.events.EventBase): The event to check.
            state_events (dict[tuple[event type, state key], EventBase]): The state of the
                room before the event was sent.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        # Get the room memberships and 3PID invite tokens from the room's state.
        existing_members, threepid_tokens = self._get_members_and_tokens_from_state(
            state_events, event
        )

        # There should never be more than one 3PID invite in the room state: if the second
        # original user came and left, and we're inviting them using their email address,
        # given we know they have a Matrix account binded to the address (so they could
        # join the first time), Synapse will successfully look it up before attempting to
        # store an invite on the IS.
        if len(threepid_tokens) == 1 and event.type == EventTypes.ThirdPartyInvite:
            # If we already have a 3PID invite in flight, don't accept another one.
            return False

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
                event, threepid_tokens[0],
            )
            if is_from_threepid_invite or target == existing_members[0]:
                return True

            return False

        return True

    def _is_power_level_content_allowed(self, content, access_rule):
        """Check if a given power levels event is permitted under the given access rule.

        It shouldn't be allowed if it either changes the default PL to a non-0 value or
        gives a non-0 PL to a user that would have been forbidden from joining the room
        under a more restrictive access rule.

        Args:
            content (dict[]): The content of the m.room.power_levels event to check.
            access_rule (str): The access rule in place in this room.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        # Check if we need to apply the restrictions with the current rule.
        if access_rule not in RULES_WITH_RESTRICTED_POWER_LEVELS:
            return True

        # If users_default is explicitly set to a non-0 value, deny the event.
        users_default = content.get('users_default', 0)
        if users_default:
            return False

        users = content.get('users', {})
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

    def _on_join_rule_change(self, event, rule):
        """Check whether a join rule change is allowed. A join rule change is always
        allowed unless the new join rule is "public" and the current access rule isn't
        "restricted".
        The rationale is that external users (those whose server would be denied access
        to rooms enforcing the "restricted" access rule) should always rely on non-
        external users for access to rooms, therefore they shouldn't be able to access
        rooms that don't require an invite to be joined.

        Note that we currently rely on the default access rule being "restricted": during
        room creation, the m.room.join_rules event will be sent *before* the
        im.vector.room.access_rules one, so the access rule that will be considered here
        in this case will be the default "restricted" one. This is fine since the
        "restricted" access rule allows any value for the join rule, but we should keep
        that in mind if we need to change the default access rule in the future.

        Args:
            event (synapse.events.EventBase): The event to check.
            rule (str): The name of the rule to apply.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        if event.content.get('join_rule') == JoinRules.PUBLIC:
            return rule == ACCESS_RULE_RESTRICTED

        return True

    def _on_room_avatar_change(self, event, rule):
        """Check whether a change of room avatar is allowed.
        The current rule is to forbid such a change in direct chats but allow it
        everywhere else.

        Args:
            event (synapse.events.EventBase): The event to check.
            rule (str): The name of the rule to apply.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        return rule != ACCESS_RULE_DIRECT

    def _on_room_name_change(self, event, rule):
        """Check whether a change of room name is allowed.
        The current rule is to forbid such a change in direct chats but allow it
        everywhere else.

        Args:
            event (synapse.events.EventBase): The event to check.
            rule (str): The name of the rule to apply.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        return rule != ACCESS_RULE_DIRECT

    def _on_room_topic_change(self, event, rule):
        """Check whether a change of room topic is allowed.
        The current rule is to forbid such a change in direct chats but allow it
        everywhere else.

        Args:
            event (synapse.events.EventBase): The event to check.
            rule (str): The name of the rule to apply.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        return rule != ACCESS_RULE_DIRECT

    @staticmethod
    def _get_rule_from_state(state_events):
        """Extract the rule to be applied from the given set of state events.

        Args:
            state_events (dict[tuple[event type, state key], EventBase]): The set of state
                events.
        Returns:
            str, the name of the rule (either "direct", "restricted" or "unrestricted")
        """
        access_rules = state_events.get((ACCESS_RULES_TYPE, ""))
        if access_rules is None:
            rule = ACCESS_RULE_RESTRICTED
        else:
            rule = access_rules.content.get("rule")
        return rule

    @staticmethod
    def _get_join_rule_from_state(state_events):
        """Extract the room's join rule from the given set of state events.

        Args:
            state_events (dict[tuple[event type, state key], EventBase]): The set of state
                events.
        Returns:
            str, the name of the join rule (either "public", or "invite")
        """
        join_rule_event = state_events.get((EventTypes.JoinRules, ""))
        if join_rule_event is None:
            return None
        return join_rule_event.content.get("join_rule")

    @staticmethod
    def _get_members_and_tokens_from_state(state_events, event):
        """Retrieves from a list of state events the list of users that have a
        m.room.member event in the room, and the tokens of 3PID invites in the room.

        Args:
            state_events (dict[tuple[event type, state key], EventBase]): The set of state
                events.
            event (EventBase): The event being checked.
        Returns:
            existing_members (list[str]): List of targets of the m.room.member events in
                the state.
            threepid_invite_tokens (list[str]): List of tokens of the 3PID invites in the
                state.
        """
        existing_members = []
        threepid_invite_tokens = []
        for key, state_event in state_events.items():
            if key[0] == EventTypes.Member and state_event.content:
                existing_members.append(state_event.state_key)
            if key[0] == EventTypes.ThirdPartyInvite and state_event.content:
                threepid_invite_tokens.append(state_event.state_key)

        # If the event is a state event, there already is an event with the same state key
        # in the room's state, then the event is updating an existing event from the
        # room's state, in which case we need to remove the entry from the list in order
        # to avoid conflicts.
        if event.is_state():
            existing_members = existing_members
            threepid_invite_tokens = filter(
                lambda sk: event.state_key != sk,
                threepid_invite_tokens,
            )

        return existing_members, list(threepid_invite_tokens)

    @staticmethod
    def _is_invite_from_threepid(invite, threepid_invite_token):
        """Checks whether the given invite follows the given 3PID invite.

        Args:
             invite (EventBase): The m.room.member event with "invite" membership.
             threepid_invite_token (str): The state key from the 3PID invite.
        """
        token = invite.content.get(
            "third_party_invite", {},
        ).get("signed", {}).get("token", "")

        return token == threepid_invite_token
