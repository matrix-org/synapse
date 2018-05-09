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

"""
DomainRuleChecker

Takes a config in the format:

spam_checker:
    module: "rulecheck.DomainRuleChecker"
    config:
      domain_mapping:
        "inviter_domain": [ "invitee_domain_permitted", "other_invitee_domain_permitted" ]
        "other_inviter_domain": [ "invitee_domain_permitted" ]
      default: False
    }

Don't forget to consider if you can invite users from your own domain.
"""


class DomainRuleChecker(object):

    def __init__(self, config):
        self.domain_mapping = config["domain_mapping"] or {}
        self.default = config["default"]

    def check_event_for_spam(self, event):
        return False

    def user_may_invite(self, inviter_userid, invitee_userid, room_id):
        inviter_domain = self._get_domain_from_id(inviter_userid)
        invitee_domain = self._get_domain_from_id(invitee_userid)

        valid_targets = self.domain_mapping.get(inviter_domain)
        if not valid_targets:
            return self.default

        return invitee_domain in valid_targets

    def user_may_create_room(self, userid):
        return True

    def user_may_create_room_alias(self, userid, room_alias):
        return True

    def user_may_publish_room(self, userid, room_id):
        return True

    @staticmethod
    def parse_config(config):
        if "default" in config:
            return config
        else:
            raise ConfigError("No default set for spam_config DomainRuleChecker")

    @staticmethod
    def _get_domain_from_id(string):
        idx = string.find(":")
        if idx == -1:
            raise Exception("Invalid ID: %r" % (string,))
        return string[idx + 1:]
