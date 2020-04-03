# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from ._base import Config


class PushConfig(Config):
    section = "push"

    def read_config(self, config, **kwargs):
        push_config = config.get("push", {})
        self.push_include_content = push_config.get("include_content", True)

        # There was a a 'redact_content' setting but mistakenly read from the
        # 'email'section'. Check for the flag in the 'push' section, and log,
        # but do not honour it to avoid nasty surprises when people upgrade.
        if push_config.get("redact_content") is not None:
            print(
                "The push.redact_content content option has never worked. "
                "Please set push.include_content if you want this behaviour"
            )

        # Now check for the one in the 'email' section and honour it,
        # with a warning.
        push_config = config.get("email") or {}
        redact_content = push_config.get("redact_content")
        if redact_content is not None:
            print(
                "The 'email.redact_content' option is deprecated: "
                "please set push.include_content instead"
            )
            self.push_include_content = not redact_content

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """
        # Clients requesting push notifications can either have the body of
        # the message sent in the notification poke along with other details
        # like the sender, or just the event ID and room ID (`event_id_only`).
        # If clients choose the former, this option controls whether the
        # notification request includes the content of the event (other details
        # like the sender are still included). For `event_id_only` push, it
        # has no effect.
        #
        # For modern android devices the notification content will still appear
        # because it is loaded by the app. iPhone, however will send a
        # notification saying only that a message arrived and who it came from.
        #
        #push:
        #  include_content: true
        """
