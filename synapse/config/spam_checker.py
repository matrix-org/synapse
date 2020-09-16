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

from typing import Any, Dict, List, Tuple

from synapse.config import ConfigError
from synapse.util.module_loader import load_module

from ._base import Config


class SpamCheckerConfig(Config):
    section = "spamchecker"

    def read_config(self, config, **kwargs):
        self.spam_checkers = []  # type: List[Tuple[Any, Dict]]

        spam_checkers = config.get("spam_checker") or []
        if isinstance(spam_checkers, dict):
            # The spam_checker config option used to only support one
            # spam checker, and thus was simply a dictionary with module
            # and config keys. Support this old behaviour by checking
            # to see if the option resolves to a dictionary
            self.spam_checkers.append(load_module(spam_checkers))
        elif isinstance(spam_checkers, list):
            for spam_checker in spam_checkers:
                if not isinstance(spam_checker, dict):
                    raise ConfigError("spam_checker syntax is incorrect")

                self.spam_checkers.append(load_module(spam_checker))
        else:
            raise ConfigError("spam_checker syntax is incorrect")

    def generate_config_section(self, **kwargs):
        return """\
        # Spam checkers are third-party modules that can block specific actions
        # of local users, such as creating rooms and registering undesirable
        # usernames, as well as remote users by redacting incoming events.
        #
        spam_checker:
           #- module: "my_custom_project.SuperSpamChecker"
           #  config:
           #    example_option: 'things'
           #- module: "some_other_project.BadEventStopper"
           #  config:
           #    example_stop_events_from: ['@bad:example.com']
        """
