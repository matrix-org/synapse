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
        for event in config.get("initial_state", []):
            if event["type"] == ACCESS_RULES_TYPE:
                # If there's already a rules event in the initial state, check if it
                # breaks the rules for "direct", and if not don't do anything else.
                if (
                    not config.get("is_direct")
                    or event["content"]["rule"] != ACCESS_RULE_DIRECT
                ):
                    return

        # Append an access rules event to be sent once every other event in initial_state
        # has been sent. If "is_direct" exists and is set to True, the rule needs to be
        # "direct", and "restricted" otherwise.
        if config.get("is_direct"):
            default_rule = ACCESS_RULE_DIRECT
        else:
            default_rule = ACCESS_RULE_RESTRICTED

        config["initial_state"].append({
            "type": ACCESS_RULES_TYPE,
            "state_key": "",
            "content": {
                "rule": default_rule,
            }
        })

    @defer.inlineCallbacks
    def check_threepid_can_be_invited(self, medium, address, state_events):
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
        new_rule = event.content.get("rule")

        # Check for invalid values.
        if (
            new_rule != ACCESS_RULE_DIRECT
            and new_rule != ACCESS_RULE_RESTRICTED
            and new_rule != ACCESS_RULE_UNRESTRICTED
        ):
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
        # "restricted" currently means that users can only invite users if their server is
        # included in a limited list of domains.
        invitee_domain = DomainRuleChecker._get_domain_from_id(event.state_key)
        return invitee_domain not in self.domains_forbidden_when_restricted

    def _apply_unrestricted(self):
        # "unrestricted" currently means that every event is allowed.
        return True

    def _apply_direct(self, event, state_events):
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
        access_rules = state_events.get((ACCESS_RULES_TYPE, ""))
        if access_rules is None:
            rule = ACCESS_RULE_RESTRICTED
        else:
            rule = access_rules.content.get("rule")
        return rule

    @staticmethod
    def _is_invite_from_threepid(invite, threepid_invite):
        token = invite.content.get("third_party_signed", {}).get("token", "")
        return token == threepid_invite.state_key
