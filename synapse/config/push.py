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
    def read_config(self, config):
        self.push_include_content = True

        push_config = config.get("push", {})
        self.push_include_content = push_config.get("include_content", True)

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        # Clients requesting push notifications can either have the body of
        # the message sent in the notification poke along with other details
        # like the sender, or just the event ID and room ID (`event_id_only`).
        # If clients choose the former, this option controls whether the
        # notification request includes the content of the event (other details
        # like the sender are still included). For `event_id_only` push, it
        # has no effect.

        # For modern android devices the notification content will still appear
        # because it is loaded by the app. iPhone, however will send a
        # notification saying only that a message arrived and who it came from.
        #
        #push:
        #   include_content: false
        """
