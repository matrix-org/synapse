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

from synapse.config._base import ConfigError

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

    def __init__(self, config):
        self.domain_mapping = config["domain_mapping"] or {}
        self.default = config["default"]

        self.can_only_join_rooms_with_invite = config.get(
            "can_only_join_rooms_with_invite", False,
        )
        self.can_only_create_one_to_one_rooms = config.get(
            "can_only_create_one_to_one_rooms", False,
        )
        self.can_only_invite_during_room_creation = config.get(
            "can_only_invite_during_room_creation", False,
        )
        self.can_invite_by_third_party_id = config.get(
            "can_invite_by_third_party_id", True,
        )
        self.domains_prevented_from_being_invited_to_published_rooms = config.get(
            "domains_prevented_from_being_invited_to_published_rooms", [],
        )

    def check_event_for_spam(self, event):
        """Implements synapse.events.SpamChecker.check_event_for_spam
        """
        return False

    def user_may_invite(self, inviter_userid, invitee_userid, third_party_invite,
                        room_id, new_room, published_room=False):
        """Implements synapse.events.SpamChecker.user_may_invite
        """
        if self.can_only_invite_during_room_creation and not new_room:
            return False

        if not self.can_invite_by_third_party_id and third_party_invite:
            return False

        # This is a third party invite (without a bound mxid), so unless we have
        # banned all third party invites (above) we allow it.
        if not invitee_userid:
            return True

        inviter_domain = self._get_domain_from_id(inviter_userid)
        invitee_domain = self._get_domain_from_id(invitee_userid)

        if inviter_domain not in self.domain_mapping:
            return self.default

        if (
            published_room and
            invitee_domain in self.domains_prevented_from_being_invited_to_published_rooms
        ):
            return False

        return invitee_domain in self.domain_mapping[inviter_domain]

    def user_may_create_room(self, userid, invite_list, third_party_invite_list,
                             cloning):
        """Implements synapse.events.SpamChecker.user_may_create_room
        """

        if cloning:
            return True

        if not self.can_invite_by_third_party_id and third_party_invite_list:
            return False

        number_of_invites = len(invite_list) + len(third_party_invite_list)

        if self.can_only_create_one_to_one_rooms and number_of_invites != 1:
            return False

        return True

    def user_may_create_room_alias(self, userid, room_alias):
        """Implements synapse.events.SpamChecker.user_may_create_room_alias
        """
        return True

    def user_may_publish_room(self, userid, room_id):
        """Implements synapse.events.SpamChecker.user_may_publish_room
        """
        return True

    def user_may_join_room(self, userid, room_id, is_invited):
        """Implements synapse.events.SpamChecker.user_may_join_room
        """
        if self.can_only_join_rooms_with_invite and not is_invited:
            return False

        return True

    @staticmethod
    def parse_config(config):
        """Implements synapse.events.SpamChecker.parse_config
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
        return mxid[idx + 1:]
