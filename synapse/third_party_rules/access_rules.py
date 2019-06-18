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

from synapse.api.constants import EventTypes
from synapse.config._base import ConfigError
from synapse.rulecheck.domain_rule_checker import DomainRuleChecker

ACCESS_RULES_TYPE = "im.vector.room.access_rules"
ACCESS_RULE_RESTRICTED = "restricted"
ACCESS_RULE_UNRESTRICTED = "unrestricted"
ACCESS_RULE_DIRECT = "direct"


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
        rules_in_initial_state = False

        # If there's a rules event in the initial state, check if it complies with the
        # spec for im.vector.room.access_rules and fix it if not.
        for event in config.get("initial_state", []):
            if event["type"] == ACCESS_RULES_TYPE:
                rules_in_initial_state = True

                rule = event["content"].get("rule")

                # Make sure the event has a valid content.
                if rule is None:
                    event["content"] = {
                        "rule": self._on_create_room_default_rule(is_direct)
                    }

                # Make sure the rule name is valid.
                if not self._is_rule_name_valid(rule):
                    event["content"]["rule"] = self._on_create_room_default_rule(
                        is_direct,
                    )

                # Make sure the rule is "direct" if the room is a direct chat.
                if is_direct and rule != ACCESS_RULE_DIRECT:
                    event["content"]["rule"] = ACCESS_RULE_DIRECT

                # Make sure the rule is not "direct" if the room isn't a direct chat.
                if rule == ACCESS_RULE_DIRECT and not is_direct:
                    event["content"]["rule"] = ACCESS_RULE_RESTRICTED

        # If there's no rules event in the initial state, create one with the default
        # setting.
        if not rules_in_initial_state:
            if not config.get("initial_state"):
                config["initial_state"] = []

            config["initial_state"].append({
                "type": ACCESS_RULES_TYPE,
                "state_key": "",
                "content": {
                    "rule": self._on_create_room_default_rule(is_direct),
                }
            })

    @staticmethod
    def _on_create_room_default_rule(is_direct):
        """Returns the default rule to set.

        Args:
            is_direct (bool): Is the room created with "is_direct" set to True.

        Returns:
            str, the name of the rule tu use as the default.
        """
        if is_direct:
            return ACCESS_RULE_DIRECT
        else:
            return ACCESS_RULE_RESTRICTED

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
            # Only "restricted" requires filtering 3PID invites.
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
        # Special-case the access rules event.
        if event.type == ACCESS_RULES_TYPE:
            return self._on_rules_change(event, state_events)

        rule = self._get_rule_from_state(state_events)

        if rule == ACCESS_RULE_RESTRICTED:
            ret = self._apply_restricted(event)
        elif rule == ACCESS_RULE_UNRESTRICTED:
            ret = self._apply_unrestricted()
        elif rule == ACCESS_RULE_DIRECT:
            ret = self._apply_direct(event, state_events)
        else:
            # We currently apply the default (restricted) if we don't know the rule, we
            # might want to change that in the future.
            ret = self._apply_restricted(event)

        return ret

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
        if not self._is_rule_name_valid(new_rule):
            return False

        # Make sure we don't apply "direct" if the room has more than two members.
        if new_rule == ACCESS_RULE_DIRECT:
            member_events_count = 0
            for key, event in state_events.items():
                if key[0] == EventTypes.Member:
                    member_events_count += 1

            if member_events_count > 2:
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

    def _apply_restricted(self, event):
        """Implements the checks and behaviour specified for the "restricted" rule.

        Args:
            event (synapse.events.EventBase): The event to check.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        # "restricted" currently means that users can only invite users if their server is
        # included in a limited list of domains.
        if event.type != EventTypes.Member and event.type != EventTypes.ThirdPartyInvite:
            return True
        invitee_domain = DomainRuleChecker._get_domain_from_id(event.state_key)
        return invitee_domain not in self.domains_forbidden_when_restricted

    def _apply_unrestricted(self):
        """Implements the checks and behaviour specified for the "unrestricted" rule.

        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        # "unrestricted" currently means that every event is allowed.
        return True

    def _apply_direct(self, event, state_events):
        """Implements the checks and behaviour specified for the "direct" rule.

        Args:
            event (synapse.events.EventBase): The event to check.
            state_events (dict[tuple[event type, state key], EventBase]): The state of the
                room before the event was sent.
        Returns:
            bool, True if the event can be allowed, False otherwise.
        """
        # "direct" currently means that no member is allowed apart from the two initial
        # members the room was created for (i.e. the room's creator and their first
        # invitee).
        if event.type != EventTypes.Member and event.type != EventTypes.ThirdPartyInvite:
            return True

        # Get the m.room.member and m.room.third_party_invite events from the room's
        # state.
        member_events = []
        threepid_invite_events = []
        for key, event in state_events.items():
            if key[0] == EventTypes.Member:
                member_events.append(event)
            if key[0] == EventTypes.ThirdPartyInvite:
                threepid_invite_events.append(event)

        # There should never be more than one 3PID invite in the room state: if the second
        # original user came and left, and we're inviting them using their email address,
        # given we know they have a Matrix account binded to the address (so they could
        # join the first time), Synapse will successfully look it up before attempting to
        # store an invite on the IS.
        if len(threepid_invite_events) == 1 and event.type == EventTypes.ThirdPartyInvite:
            # If we already have a 3PID invite in flight, don't accept another one.
            return False

        if len(member_events) == 2:
            # If the user was within the two initial user of the room, Synapse would have
            # looked it up successfully and thus sent a m.room.member here instead of
            # m.room.third_party_invite.
            if event.type == EventTypes.ThirdPartyInvite:
                return False

            # We can only have m.room.member events here. The rule in this case is to only
            # allow the event if its target is one of the initial two members in the room,
            # i.e. the state key of one of the two m.room.member states in the room.
            target = event.state_key
            for e in member_events:
                if e.state_key == target:
                    return True

            return False

        # We're alone in the room (and always have been) and there's one 3PID invite in
        # flight.
        if len(member_events) == 1 and len(threepid_invite_events) == 1:
            # We can only have m.room.member events here. In this case, we can only allow
            # the event if it's either a m.room.member from the joined user (we can assume
            # that the only m.room.member event is a join otherwise we wouldn't be able to
            # send an event to the room) or an an invite event which target is the invited
            # user.
            target = event.state_key
            is_from_threepid_invite = self._is_invite_from_threepid(
                event, threepid_invite_events[0],

            )
            if is_from_threepid_invite or target == member_events[0].state_key:
                return True

            return False

        return True

    @staticmethod
    def _get_rule_from_state(state_events):
        """Extract the rule to be applied from the given set of state events.

        Args:
            state_events (dict[tuple[event type, state key], EventBase]): The set of state
                events
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
    def _is_invite_from_threepid(invite, threepid_invite):
        """Checks whether the given invite follows the given 3PID invite.

        Args:
             invite (EventBase): The m.room.member event with "invite" membership.
             threepid_invite (EventBase): The m.room.third_party_invite event.
        """
        token = invite.content.get("third_party_signed", {}).get("token", "")
        return token == threepid_invite.state_key

    @staticmethod
    def _is_rule_name_valid(rule):
        """Returns whether the given rule name is within the allowed values ("direct",
        "restricted" or "unrestricted").

        Args:
            rule (str): The name of the rule.
        Returns:
            bool, True if the name is valid, False otherwise.
        """
        return (
            rule == ACCESS_RULE_DIRECT
            or rule == ACCESS_RULE_RESTRICTED
            or rule == ACCESS_RULE_UNRESTRICTED
        )
