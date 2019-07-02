# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd
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


class SpamCheckerConfig(Config):
    def read_config(self, config, **kwargs):
        self.spam_checker = None

        provider = config.get("spam_checker", None)
        if provider is not None:
            self.spam_checker = load_module(provider)

    def generate_config_section(self, **kwargs):
        return """\
        #spam_checker:
        #  module: "my_custom_project.SuperSpamChecker"
        #  config:
        #    example_option: 'things'
        """
