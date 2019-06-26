# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

from synapse.util.module_loader import load_module

from ._base import Config


class ThirdPartyRulesConfig(Config):
    def read_config(self, config, **kwargs):
        self.third_party_event_rules = None

        provider = config.get("third_party_event_rules", None)
        if provider is not None:
            self.third_party_event_rules = load_module(provider)

    def generate_config_section(self, **kwargs):
        return """\
        # Server admins can define a Python module that implements extra rules for
        # allowing or denying incoming events. In order to work, this module needs to
        # override the methods defined in synapse/events/third_party_rules.py.
        #
        # This feature is designed to be used in closed federations only, where each
        # participating server enforces the same rules.
        #
        #third_party_event_rules:
        #  module: "my_custom_project.SuperRulesSet"
        #  config:
        #    example_option: 'things'
        """
