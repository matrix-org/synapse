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

from twisted.internet import defer


class TchapEventRules(object):

    ACESS_RULES_TYPE = "im.vector.room.access_rules"

    def __init__(self, config):
        # We don't have a config yet.
        pass

    @staticmethod
    def parse_config(config):
        return config

    @defer.inlineCallbacks
    def check_event_allowed(self, event, context):
        return True

    def _apply_restricted(self):
        pass

    def _apply_unrestricted(self):
        pass

    def _apply_direct(self):
        pass
