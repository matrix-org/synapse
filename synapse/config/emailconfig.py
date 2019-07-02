# -*- coding: utf-8 -*-
# Copyright 2015-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
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

from __future__ import print_function

# This file can't be called email.py because if it is, we cannot:
import email.utils
import os

import pkg_resources

from ._base import Config, ConfigError


class EmailConfig(Config):
    def read_config(self, config, **kwargs):
        # TODO: We should separate better the email configuration from the notification
        # and account validity config.

        self.email_enable_notifs = False

        email_config = config.get("email", {})

        self.email_smtp_host = email_config.get("smtp_host", None)
        self.email_smtp_port = email_config.get("smtp_port", None)
        self.email_smtp_user = email_config.get("smtp_user", None)
        self.email_smtp_pass = email_config.get("smtp_pass", None)
        self.require_transport_security = email_config.get(
            "require_transport_security", False
        )
        if "app_name" in email_config:
            self.email_app_name = email_config["app_name"]
        else:
            self.email_app_name = "Matrix"

        # TODO: Rename notif_from to something more generic, or have a separate
        # from for password resets, message notifications, etc?
        # Currently the email section is a bit bogged down with settings for
        # multiple functions. Would be good to split it out into separate
        # sections and only put the common ones under email:
        self.email_notif_from = email_config.get("notif_from", None)
        if self.email_notif_from is not None:
            # make sure it's valid
            parsed = email.utils.parseaddr(self.email_notif_from)
            if parsed[1] == "":
                raise RuntimeError("Invalid notif_from address")

        template_dir = email_config.get("template_dir")
        # we need an absolute path, because we change directory after starting (and
        # we don't yet know what auxilliary templates like mail.css we will need).
        # (Note that loading as package_resources with jinja.PackageLoader doesn't
        # work for the same reason.)
        if not template_dir:
            template_dir = pkg_resources.resource_filename("synapse", "res/templates")

        self.email_template_dir = os.path.abspath(template_dir)

        self.email_enable_notifs = email_config.get("enable_notifs", False)
        account_validity_renewal_enabled = config.get("account_validity", {}).get(
            "renew_at"
        )

        email_trust_identity_server_for_password_resets = email_config.get(
            "trust_identity_server_for_password_resets", False
        )
        self.email_password_reset_behaviour = (
            "remote" if email_trust_identity_server_for_password_resets else "local"
        )
        self.password_resets_were_disabled_due_to_email_config = False
        if self.email_password_reset_behaviour == "local" and email_config == {}:
            # We cannot warn the user this has happened here
            # Instead do so when a user attempts to reset their password
            self.password_resets_were_disabled_due_to_email_config = True

            self.email_password_reset_behaviour = "off"

        # Get lifetime of a validation token in milliseconds
        self.email_validation_token_lifetime = self.parse_duration(
            email_config.get("validation_token_lifetime", "1h")
        )

        if (
            self.email_enable_notifs
            or account_validity_renewal_enabled
            or self.email_password_reset_behaviour == "local"
        ):
            # make sure we can import the required deps
            import jinja2
            import bleach

            # prevent unused warnings
            jinja2
            bleach

        if self.email_password_reset_behaviour == "local":
            required = ["smtp_host", "smtp_port", "notif_from"]

            missing = []
            for k in required:
                if k not in email_config:
                    missing.append(k)

            if len(missing) > 0:
                raise RuntimeError(
                    "email.password_reset_behaviour is set to 'local' "
                    "but required keys are missing: %s"
                    % (", ".join(["email." + k for k in missing]),)
                )

            # Templates for password reset emails
            self.email_password_reset_template_html = email_config.get(
                "password_reset_template_html", "password_reset.html"
            )
            self.email_password_reset_template_text = email_config.get(
                "password_reset_template_text", "password_reset.txt"
            )
            self.email_password_reset_failure_template = email_config.get(
                "password_reset_failure_template", "password_reset_failure.html"
            )
            # This template does not support any replaceable variables, so we will
            # read it from the disk once during setup
            email_password_reset_success_template = email_config.get(
                "password_reset_success_template", "password_reset_success.html"
            )

            # Check templates exist
            for f in [
                self.email_password_reset_template_html,
                self.email_password_reset_template_text,
                self.email_password_reset_failure_template,
                email_password_reset_success_template,
            ]:
                p = os.path.join(self.email_template_dir, f)
                if not os.path.isfile(p):
                    raise ConfigError("Unable to find template file %s" % (p,))

            # Retrieve content of web templates
            filepath = os.path.join(
                self.email_template_dir, email_password_reset_success_template
            )
            self.email_password_reset_success_html_content = self.read_file(
                filepath, "email.password_reset_template_success_html"
            )

            if config.get("public_baseurl") is None:
                raise RuntimeError(
                    "email.password_reset_behaviour is set to 'local' but no "
                    "public_baseurl is set. This is necessary to generate password "
                    "reset links"
                )

        if self.email_enable_notifs:
            required = [
                "smtp_host",
                "smtp_port",
                "notif_from",
                "notif_template_html",
                "notif_template_text",
            ]

            missing = []
            for k in required:
                if k not in email_config:
                    missing.append(k)

            if len(missing) > 0:
                raise RuntimeError(
                    "email.enable_notifs is True but required keys are missing: %s"
                    % (", ".join(["email." + k for k in missing]),)
                )

            if config.get("public_baseurl") is None:
                raise RuntimeError(
                    "email.enable_notifs is True but no public_baseurl is set"
                )

            self.email_notif_template_html = email_config["notif_template_html"]
            self.email_notif_template_text = email_config["notif_template_text"]

            for f in self.email_notif_template_text, self.email_notif_template_html:
                p = os.path.join(self.email_template_dir, f)
                if not os.path.isfile(p):
                    raise ConfigError("Unable to find email template file %s" % (p,))

            self.email_notif_for_new_users = email_config.get(
                "notif_for_new_users", True
            )
            self.email_riot_base_url = email_config.get("riot_base_url", None)

        if account_validity_renewal_enabled:
            self.email_expiry_template_html = email_config.get(
                "expiry_template_html", "notice_expiry.html"
            )
            self.email_expiry_template_text = email_config.get(
                "expiry_template_text", "notice_expiry.txt"
            )

            for f in self.email_expiry_template_text, self.email_expiry_template_html:
                p = os.path.join(self.email_template_dir, f)
                if not os.path.isfile(p):
                    raise ConfigError("Unable to find email template file %s" % (p,))

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """
        # Enable sending emails for password resets, notification events or
        # account expiry notices
        #
        # If your SMTP server requires authentication, the optional smtp_user &
        # smtp_pass variables should be used
        #
        #email:
        #   enable_notifs: false
        #   smtp_host: "localhost"
        #   smtp_port: 25 # SSL: 465, STARTTLS: 587
        #   smtp_user: "exampleusername"
        #   smtp_pass: "examplepassword"
        #   require_transport_security: False
        #   notif_from: "Your Friendly %(app)s Home Server <noreply@example.com>"
        #   app_name: Matrix
        #
        #   # Enable email notifications by default
        #   #
        #   notif_for_new_users: True
        #
        #   # Defining a custom URL for Riot is only needed if email notifications
        #   # should contain links to a self-hosted installation of Riot; when set
        #   # the "app_name" setting is ignored
        #   #
        #   riot_base_url: "http://localhost/riot"
        #
        #   # Enable sending password reset emails via the configured, trusted
        #   # identity servers
        #   #
        #   # IMPORTANT! This will give a malicious or overtaken identity server
        #   # the ability to reset passwords for your users! Make absolutely sure
        #   # that you want to do this! It is strongly recommended that password
        #   # reset emails be sent by the homeserver instead
        #   #
        #   # If this option is set to false and SMTP options have not been
        #   # configured, resetting user passwords via email will be disabled
        #   #
        #   #trust_identity_server_for_password_resets: false
        #
        #   # Configure the time that a validation email or text message code
        #   # will expire after sending
        #   #
        #   # This is currently used for password resets
        #   #
        #   #validation_token_lifetime: 1h
        #
        #   # Template directory. All template files should be stored within this
        #   # directory. If not set, default templates from within the Synapse
        #   # package will be used
        #   #
        #   # For the list of default templates, please see
        #   # https://github.com/matrix-org/synapse/tree/master/synapse/res/templates
        #   #
        #   #template_dir: res/templates
        #
        #   # Templates for email notifications
        #   #
        #   notif_template_html: notif_mail.html
        #   notif_template_text: notif_mail.txt
        #
        #   # Templates for account expiry notices
        #   #
        #   expiry_template_html: notice_expiry.html
        #   expiry_template_text: notice_expiry.txt
        #
        #   # Templates for password reset emails sent by the homeserver
        #   #
        #   #password_reset_template_html: password_reset.html
        #   #password_reset_template_text: password_reset.txt
        #
        #   # Templates for password reset success and failure pages that a user
        #   # will see after attempting to reset their password
        #   #
        #   #password_reset_template_success_html: password_reset_success.html
        #   #password_reset_template_failure_html: password_reset_failure.html
        """
