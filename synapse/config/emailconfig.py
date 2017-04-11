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
    def read_config(self, config):
        self.email_enable_notifs = False

        email_config = config.get("email", {})
        self.email_enable_notifs = email_config.get("enable_notifs", False)

        if self.email_enable_notifs:
            # make sure we can import the required deps
            import jinja2
            import bleach
            # prevent unused warnings
            jinja2
            bleach

            required = [
                "smtp_host",
                "smtp_port",
                "notif_from",
                "template_dir",
                "notif_template_html",
                "notif_template_text",
            ]

            missing = []
            for k in required:
                if k not in email_config:
                    missing.append(k)

            if (len(missing) > 0):
                raise RuntimeError(
                    "email.enable_notifs is True but required keys are missing: %s" %
                    (", ".join(["email." + k for k in missing]),)
                )

            if config.get("public_baseurl") is None:
                raise RuntimeError(
                    "email.enable_notifs is True but no public_baseurl is set"
                )

            self.email_smtp_host = email_config["smtp_host"]
            self.email_smtp_port = email_config["smtp_port"]
            self.email_notif_from = email_config["notif_from"]
            self.email_template_dir = email_config["template_dir"]
            self.email_notif_template_html = email_config["notif_template_html"]
            self.email_notif_template_text = email_config["notif_template_text"]
            self.email_notif_for_new_users = email_config.get(
                "notif_for_new_users", True
            )
            self.email_riot_base_url = email_config.get(
                "riot_base_url", None
            )
            self.email_smtp_user = email_config.get(
                "smtp_user", None
            )
            self.email_smtp_pass = email_config.get(
                "smtp_pass", None
            )
            self.require_transport_security = email_config.get(
                "require_transport_security", False
            )
            if "app_name" in email_config:
                self.email_app_name = email_config["app_name"]
            else:
                self.email_app_name = "Matrix"

            # make sure it's valid
            parsed = email.utils.parseaddr(self.email_notif_from)
            if parsed[1] == '':
                raise RuntimeError("Invalid notif_from address")
        else:
            self.email_enable_notifs = False
            # Not much point setting defaults for the rest: it would be an
            # error for them to be used.

    def default_config(self, config_dir_path, server_name, **kwargs):
        return """
        # Enable sending emails for notification events
        # Defining a custom URL for Riot is only needed if email notifications
        # should contain links to a self-hosted installation of Riot; when set
        # the "app_name" setting is ignored.
        #
        # If your SMTP server requires authentication, the optional smtp_user &
        # smtp_pass variables should be used
        #
        #email:
        #   enable_notifs: false
        #   smtp_host: "localhost"
        #   smtp_port: 25
        #   smtp_user: "exampleusername"
        #   smtp_pass: "examplepassword"
        #   require_transport_security: False
        #   notif_from: "Your Friendly %(app)s Home Server <noreply@example.com>"
        #   app_name: Matrix
        #   template_dir: res/templates
        #   notif_template_html: notif_mail.html
        #   notif_template_text: notif_mail.txt
        #   notif_for_new_users: True
        #   riot_base_url: "http://localhost/riot"
        """
