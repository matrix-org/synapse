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
from enum import Enum

import pkg_resources

from ._base import Config, ConfigError


class EmailConfig(Config):
    section = "email"

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

        self.threepid_behaviour_email = (
            # Have Synapse handle the email sending if account_threepid_delegates.email
            # is not defined
            # msisdn is currently always remote while Synapse does not support any method of
            # sending SMS messages
            ThreepidBehaviour.REMOTE
            if self.account_threepid_delegate_email
            else ThreepidBehaviour.LOCAL
        )
        # Prior to Synapse v1.4.0, there was another option that defined whether Synapse would
        # use an identity server to password reset tokens on its behalf. We now warn the user
        # if they have this set and tell them to use the updated option, while using a default
        # identity server in the process.
        self.using_identity_server_from_trusted_list = False
        if (
            not self.account_threepid_delegate_email
            and config.get("trust_identity_server_for_password_resets", False) is True
        ):
            # Use the first entry in self.trusted_third_party_id_servers instead
            if self.trusted_third_party_id_servers:
                # XXX: It's a little confusing that account_threepid_delegate_email is modified
                # both in RegistrationConfig and here. We should factor this bit out
                self.account_threepid_delegate_email = self.trusted_third_party_id_servers[
                    0
                ]
                self.using_identity_server_from_trusted_list = True
            else:
                raise ConfigError(
                    "Attempted to use an identity server from"
                    '"trusted_third_party_id_servers" but it is empty.'
                )

        self.local_threepid_handling_disabled_due_to_email_config = False
        if (
            self.threepid_behaviour_email == ThreepidBehaviour.LOCAL
            and email_config == {}
        ):
            # We cannot warn the user this has happened here
            # Instead do so when a user attempts to reset their password
            self.local_threepid_handling_disabled_due_to_email_config = True

            self.threepid_behaviour_email = ThreepidBehaviour.OFF

        # Get lifetime of a validation token in milliseconds
        self.email_validation_token_lifetime = self.parse_duration(
            email_config.get("validation_token_lifetime", "1h")
        )

        if (
            self.email_enable_notifs
            or account_validity_renewal_enabled
            or self.threepid_behaviour_email == ThreepidBehaviour.LOCAL
        ):
            # make sure we can import the required deps
            import jinja2
            import bleach

            # prevent unused warnings
            jinja2
            bleach

        if self.threepid_behaviour_email == ThreepidBehaviour.LOCAL:
            required = ["smtp_host", "smtp_port", "notif_from"]

            missing = []
            for k in required:
                if k not in email_config:
                    missing.append("email." + k)

            # public_baseurl is required to build password reset and validation links that
            # will be emailed to users
            if config.get("public_baseurl") is None:
                missing.append("public_baseurl")

            if len(missing) > 0:
                raise RuntimeError(
                    "Password resets emails are configured to be sent from "
                    "this homeserver due to a partial 'email' block. "
                    "However, the following required keys are missing: %s"
                    % (", ".join(missing),)
                )

            # These email templates have placeholders in them, and thus must be
            # parsed using a templating engine during a request
            self.email_password_reset_template_html = email_config.get(
                "password_reset_template_html", "password_reset.html"
            )
            self.email_password_reset_template_text = email_config.get(
                "password_reset_template_text", "password_reset.txt"
            )
            self.email_registration_template_html = email_config.get(
                "registration_template_html", "registration.html"
            )
            self.email_registration_template_text = email_config.get(
                "registration_template_text", "registration.txt"
            )
            self.email_add_threepid_template_html = email_config.get(
                "add_threepid_template_html", "add_threepid.html"
            )
            self.email_add_threepid_template_text = email_config.get(
                "add_threepid_template_text", "add_threepid.txt"
            )

            self.email_password_reset_template_failure_html = email_config.get(
                "password_reset_template_failure_html", "password_reset_failure.html"
            )
            self.email_registration_template_failure_html = email_config.get(
                "registration_template_failure_html", "registration_failure.html"
            )
            self.email_add_threepid_template_failure_html = email_config.get(
                "add_threepid_template_failure_html", "add_threepid_failure.html"
            )

            # These templates do not support any placeholder variables, so we
            # will read them from disk once during setup
            email_password_reset_template_success_html = email_config.get(
                "password_reset_template_success_html", "password_reset_success.html"
            )
            email_registration_template_success_html = email_config.get(
                "registration_template_success_html", "registration_success.html"
            )
            email_add_threepid_template_success_html = email_config.get(
                "add_threepid_template_success_html", "add_threepid_success.html"
            )

            # Check templates exist
            for f in [
                self.email_password_reset_template_html,
                self.email_password_reset_template_text,
                self.email_registration_template_html,
                self.email_registration_template_text,
                self.email_add_threepid_template_html,
                self.email_add_threepid_template_text,
                self.email_password_reset_template_failure_html,
                self.email_registration_template_failure_html,
                self.email_add_threepid_template_failure_html,
                email_password_reset_template_success_html,
                email_registration_template_success_html,
                email_add_threepid_template_success_html,
            ]:
                p = os.path.join(self.email_template_dir, f)
                if not os.path.isfile(p):
                    raise ConfigError("Unable to find template file %s" % (p,))

            # Retrieve content of web templates
            filepath = os.path.join(
                self.email_template_dir, email_password_reset_template_success_html
            )
            self.email_password_reset_template_success_html = self.read_file(
                filepath, "email.password_reset_template_success_html"
            )
            filepath = os.path.join(
                self.email_template_dir, email_registration_template_success_html
            )
            self.email_registration_template_success_html_content = self.read_file(
                filepath, "email.registration_template_success_html"
            )
            filepath = os.path.join(
                self.email_template_dir, email_add_threepid_template_success_html
            )
            self.email_add_threepid_template_success_html_content = self.read_file(
                filepath, "email.add_threepid_template_success_html"
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
        #   require_transport_security: false
        #   notif_from: "Your Friendly %(app)s homeserver <noreply@example.com>"
        #   app_name: Matrix
        #
        #   # Enable email notifications by default
        #   #
        #   notif_for_new_users: true
        #
        #   # Defining a custom URL for Riot is only needed if email notifications
        #   # should contain links to a self-hosted installation of Riot; when set
        #   # the "app_name" setting is ignored
        #   #
        #   riot_base_url: "http://localhost/riot"
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
        #   # Templates for registration emails sent by the homeserver
        #   #
        #   #registration_template_html: registration.html
        #   #registration_template_text: registration.txt
        #
        #   # Templates for validation emails sent by the homeserver when adding an email to
        #   # your user account
        #   #
        #   #add_threepid_template_html: add_threepid.html
        #   #add_threepid_template_text: add_threepid.txt
        #
        #   # Templates for password reset success and failure pages that a user
        #   # will see after attempting to reset their password
        #   #
        #   #password_reset_template_success_html: password_reset_success.html
        #   #password_reset_template_failure_html: password_reset_failure.html
        #
        #   # Templates for registration success and failure pages that a user
        #   # will see after attempting to register using an email or phone
        #   #
        #   #registration_template_success_html: registration_success.html
        #   #registration_template_failure_html: registration_failure.html
        #
        #   # Templates for success and failure pages that a user will see after attempting
        #   # to add an email or phone to their account
        #   #
        #   #add_threepid_success_html: add_threepid_success.html
        #   #add_threepid_failure_html: add_threepid_failure.html
        """


class ThreepidBehaviour(Enum):
    """
    Enum to define the behaviour of Synapse with regards to when it contacts an identity
    server for 3pid registration and password resets

    REMOTE = use an external server to send tokens
    LOCAL = send tokens ourselves
    OFF = disable registration via 3pid and password resets
    """

    REMOTE = "remote"
    LOCAL = "local"
    OFF = "off"
