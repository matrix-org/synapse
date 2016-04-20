# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

# This file can't be called email.py because if it is, we cannot:
import email.utils

from ._base import Config


class EmailConfig(Config):
    """
    Email Configuration
    """

    def read_config(self, config):
        email_config = config.get("email", None)
        if email_config:
            self.email_enable_notifs = email_config.get("enable_notifs", True)
            if (
                "smtp_host" not in email_config or
                "smtp_port" not in email_config or
                "notif_from" not in email_config
            ):
                raise RuntimeError(
                    "You must set smtp_host, smtp_port and notif_from "
                    "to send email notifications"
                )

            self.email_smtp_host = email_config["smtp_host"]
            self.email_smtp_port = email_config["smtp_port"]
            self.email_notif_from = email_config["notif_from"]

            # make sure it's valid
            parsed = email.utils.parseaddr(self.email_notif_from)
            if parsed[1] == '':
                raise RuntimeError("Invalid notif_from address")
        else:
            self.email_enable_notifs = False
            self.email_smtp_host = None
            self.email_smtp_port = None
            self.email_notif_from = None

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        # Enable sending emails for notification events
        #email_config:
        #   enable_notifs: false
        #   smtp_host: "localhost"
        #   smtp_port: 25
        """
