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

# This file can't be called email.py because if it is, we cannot:
import email.utils
import os
from enum import Enum
from typing import Optional

import attr

from ._base import Config, ConfigError

MISSING_PASSWORD_RESET_CONFIG_ERROR = """\
Password reset emails are enabled on this homeserver due to a partial
'email' block. However, the following required keys are missing:
    %s
"""

DEFAULT_SUBJECTS = {
    "message_from_person_in_room": "[%(app)s] You have a message on %(app)s from %(person)s in the %(room)s room...",
    "message_from_person": "[%(app)s] You have a message on %(app)s from %(person)s...",
    "messages_from_person": "[%(app)s] You have messages on %(app)s from %(person)s...",
    "messages_in_room": "[%(app)s] You have messages on %(app)s in the %(room)s room...",
    "messages_in_room_and_others": "[%(app)s] You have messages on %(app)s in the %(room)s room and others...",
    "messages_from_person_and_others": "[%(app)s] You have messages on %(app)s from %(person)s and others...",
    "invite_from_person": "[%(app)s] %(person)s has invited you to chat on %(app)s...",
    "invite_from_person_to_room": "[%(app)s] %(person)s has invited you to join the %(room)s room on %(app)s...",
    "password_reset": "[%(server_name)s] Password reset",
    "email_validation": "[%(server_name)s] Validate your email",
}


@attr.s
class EmailSubjectConfig:
    message_from_person_in_room = attr.ib(type=str)
    message_from_person = attr.ib(type=str)
    messages_from_person = attr.ib(type=str)
    messages_in_room = attr.ib(type=str)
    messages_in_room_and_others = attr.ib(type=str)
    messages_from_person_and_others = attr.ib(type=str)
    invite_from_person = attr.ib(type=str)
    invite_from_person_to_room = attr.ib(type=str)
    password_reset = attr.ib(type=str)
    email_validation = attr.ib(type=str)


class EmailConfig(Config):
    section = "email"

    def read_config(self, config, **kwargs):
        # TODO: We should separate better the email configuration from the notification
        # and account validity config.

        self.email_enable_notifs = False

        email_config = config.get("email")
        if email_config is None:
            email_config = {}

        self.email_smtp_host = email_config.get("smtp_host", "localhost")
        self.email_smtp_port = email_config.get("smtp_port", 25)
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

        # A user-configurable template directory
        template_dir = email_config.get("template_dir")
        if isinstance(template_dir, str):
            # We need an absolute path, because we change directory after starting (and
            # we don't yet know what auxiliary templates like mail.css we will need).
            template_dir = os.path.abspath(template_dir)
        elif template_dir is not None:
            # If template_dir is something other than a str or None, warn the user
            raise ConfigError("Config option email.template_dir must be type str")

        self.email_enable_notifs = email_config.get("enable_notifs", False)

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

                first_trusted_identity_server = self.trusted_third_party_id_servers[0]

                # trusted_third_party_id_servers does not contain a scheme whereas
                # account_threepid_delegate_email is expected to. Presume https
                self.account_threepid_delegate_email = (
                    "https://" + first_trusted_identity_server
                )  # type: Optional[str]
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

        if self.threepid_behaviour_email == ThreepidBehaviour.LOCAL:
            missing = []
            if not self.email_notif_from:
                missing.append("email.notif_from")

            # public_baseurl is required to build password reset and validation links that
            # will be emailed to users
            if config.get("public_baseurl") is None:
                missing.append("public_baseurl")

            if missing:
                raise ConfigError(
                    MISSING_PASSWORD_RESET_CONFIG_ERROR % (", ".join(missing),)
                )

            # These email templates have placeholders in them, and thus must be
            # parsed using a templating engine during a request
            password_reset_template_html = email_config.get(
                "password_reset_template_html", "password_reset.html"
            )
            password_reset_template_text = email_config.get(
                "password_reset_template_text", "password_reset.txt"
            )
            registration_template_html = email_config.get(
                "registration_template_html", "registration.html"
            )
            registration_template_text = email_config.get(
                "registration_template_text", "registration.txt"
            )
            add_threepid_template_html = email_config.get(
                "add_threepid_template_html", "add_threepid.html"
            )
            add_threepid_template_text = email_config.get(
                "add_threepid_template_text", "add_threepid.txt"
            )

            password_reset_template_failure_html = email_config.get(
                "password_reset_template_failure_html", "password_reset_failure.html"
            )
            registration_template_failure_html = email_config.get(
                "registration_template_failure_html", "registration_failure.html"
            )
            add_threepid_template_failure_html = email_config.get(
                "add_threepid_template_failure_html", "add_threepid_failure.html"
            )

            # These templates do not support any placeholder variables, so we
            # will read them from disk once during setup
            password_reset_template_success_html = email_config.get(
                "password_reset_template_success_html", "password_reset_success.html"
            )
            registration_template_success_html = email_config.get(
                "registration_template_success_html", "registration_success.html"
            )
            add_threepid_template_success_html = email_config.get(
                "add_threepid_template_success_html", "add_threepid_success.html"
            )

            # Read all templates from disk
            (
                self.email_password_reset_template_html,
                self.email_password_reset_template_text,
                self.email_registration_template_html,
                self.email_registration_template_text,
                self.email_add_threepid_template_html,
                self.email_add_threepid_template_text,
                self.email_password_reset_template_confirmation_html,
                self.email_password_reset_template_failure_html,
                self.email_registration_template_failure_html,
                self.email_add_threepid_template_failure_html,
                password_reset_template_success_html_template,
                registration_template_success_html_template,
                add_threepid_template_success_html_template,
            ) = self.read_templates(
                [
                    password_reset_template_html,
                    password_reset_template_text,
                    registration_template_html,
                    registration_template_text,
                    add_threepid_template_html,
                    add_threepid_template_text,
                    "password_reset_confirmation.html",
                    password_reset_template_failure_html,
                    registration_template_failure_html,
                    add_threepid_template_failure_html,
                    password_reset_template_success_html,
                    registration_template_success_html,
                    add_threepid_template_success_html,
                ],
                template_dir,
            )

            # Render templates that do not contain any placeholders
            self.email_password_reset_template_success_html_content = (
                password_reset_template_success_html_template.render()
            )
            self.email_registration_template_success_html_content = (
                registration_template_success_html_template.render()
            )
            self.email_add_threepid_template_success_html_content = (
                add_threepid_template_success_html_template.render()
            )

        if self.email_enable_notifs:
            missing = []
            if not self.email_notif_from:
                missing.append("email.notif_from")

            if config.get("public_baseurl") is None:
                missing.append("public_baseurl")

            if missing:
                raise ConfigError(
                    "email.enable_notifs is True but required keys are missing: %s"
                    % (", ".join(missing),)
                )

            notif_template_html = email_config.get(
                "notif_template_html", "notif_mail.html"
            )
            notif_template_text = email_config.get(
                "notif_template_text", "notif_mail.txt"
            )

            (
                self.email_notif_template_html,
                self.email_notif_template_text,
            ) = self.read_templates(
                [notif_template_html, notif_template_text], template_dir,
            )

            self.email_notif_for_new_users = email_config.get(
                "notif_for_new_users", True
            )
            self.email_riot_base_url = email_config.get(
                "client_base_url", email_config.get("riot_base_url", None)
            )

        if self.account_validity.renew_by_email_enabled:
            expiry_template_html = email_config.get(
                "expiry_template_html", "notice_expiry.html"
            )
            expiry_template_text = email_config.get(
                "expiry_template_text", "notice_expiry.txt"
            )

            (
                self.account_validity_template_html,
                self.account_validity_template_text,
            ) = self.read_templates(
                [expiry_template_html, expiry_template_text], template_dir,
            )

        subjects_config = email_config.get("subjects", {})
        subjects = {}

        for key, default in DEFAULT_SUBJECTS.items():
            subjects[key] = subjects_config.get(key, default)

        self.email_subjects = EmailSubjectConfig(**subjects)

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return (
            """\
        # Configuration for sending emails from Synapse.
        #
        email:
          # The hostname of the outgoing SMTP server to use. Defaults to 'localhost'.
          #
          #smtp_host: mail.server

          # The port on the mail server for outgoing SMTP. Defaults to 25.
          #
          #smtp_port: 587

          # Username/password for authentication to the SMTP server. By default, no
          # authentication is attempted.
          #
          #smtp_user: "exampleusername"
          #smtp_pass: "examplepassword"

          # Uncomment the following to require TLS transport security for SMTP.
          # By default, Synapse will connect over plain text, and will then switch to
          # TLS via STARTTLS *if the SMTP server supports it*. If this option is set,
          # Synapse will refuse to connect unless the server supports STARTTLS.
          #
          #require_transport_security: true

          # notif_from defines the "From" address to use when sending emails.
          # It must be set if email sending is enabled.
          #
          # The placeholder '%%(app)s' will be replaced by the application name,
          # which is normally 'app_name' (below), but may be overridden by the
          # Matrix client application.
          #
          # Note that the placeholder must be written '%%(app)s', including the
          # trailing 's'.
          #
          #notif_from: "Your Friendly %%(app)s homeserver <noreply@example.com>"

          # app_name defines the default value for '%%(app)s' in notif_from and email
          # subjects. It defaults to 'Matrix'.
          #
          #app_name: my_branded_matrix_server

          # Uncomment the following to enable sending emails for messages that the user
          # has missed. Disabled by default.
          #
          #enable_notifs: true

          # Uncomment the following to disable automatic subscription to email
          # notifications for new users. Enabled by default.
          #
          #notif_for_new_users: false

          # Custom URL for client links within the email notifications. By default
          # links will be based on "https://matrix.to".
          #
          # (This setting used to be called riot_base_url; the old name is still
          # supported for backwards-compatibility but is now deprecated.)
          #
          #client_base_url: "http://localhost/riot"

          # Configure the time that a validation email will expire after sending.
          # Defaults to 1h.
          #
          #validation_token_lifetime: 15m

          # Directory in which Synapse will try to find the template files below.
          # If not set, default templates from within the Synapse package will be used.
          #
          # Do not uncomment this setting unless you want to customise the templates.
          #
          # Synapse will look for the following templates in this directory:
          #
          # * The contents of email notifications of missed events: 'notif_mail.html' and
          #   'notif_mail.txt'.
          #
          # * The contents of account expiry notice emails: 'notice_expiry.html' and
          #   'notice_expiry.txt'.
          #
          # * The contents of password reset emails sent by the homeserver:
          #   'password_reset.html' and 'password_reset.txt'
          #
          # * An HTML page that a user will see when they follow the link in the password
          #   reset email. The user will be asked to confirm the action before their
          #   password is reset: 'password_reset_confirmation.html'
          #
          # * HTML pages for success and failure that a user will see when they confirm
          #   the password reset flow using the page above: 'password_reset_success.html'
          #   and 'password_reset_failure.html'
          #
          # * The contents of address verification emails sent during registration:
          #   'registration.html' and 'registration.txt'
          #
          # * HTML pages for success and failure that a user will see when they follow
          #   the link in an address verification email sent during registration:
          #   'registration_success.html' and 'registration_failure.html'
          #
          # * The contents of address verification emails sent when an address is added
          #   to a Matrix account: 'add_threepid.html' and 'add_threepid.txt'
          #
          # * HTML pages for success and failure that a user will see when they follow
          #   the link in an address verification email sent when an address is added
          #   to a Matrix account: 'add_threepid_success.html' and
          #   'add_threepid_failure.html'
          #
          # You can see the default templates at:
          # https://github.com/matrix-org/synapse/tree/master/synapse/res/templates
          #
          #template_dir: "res/templates"

          # Subjects to use when sending emails from Synapse.
          #
          # The placeholder '%%(app)s' will be replaced with the value of the 'app_name'
          # setting above, or by a value dictated by the Matrix client application.
          #
          # If a subject isn't overridden in this configuration file, the value used as
          # its example will be used.
          #
          #subjects:

            # Subjects for notification emails.
            #
            # On top of the '%%(app)s' placeholder, these can use the following
            # placeholders:
            #
            #   * '%%(person)s', which will be replaced by the display name of the user(s)
            #      that sent the message(s), e.g. "Alice and Bob".
            #   * '%%(room)s', which will be replaced by the name of the room the
            #      message(s) have been sent to, e.g. "My super room".
            #
            # See the example provided for each setting to see which placeholder can be
            # used and how to use them.
            #
            # Subject to use to notify about one message from one or more user(s) in a
            # room which has a name.
            #message_from_person_in_room: "%(message_from_person_in_room)s"
            #
            # Subject to use to notify about one message from one or more user(s) in a
            # room which doesn't have a name.
            #message_from_person: "%(message_from_person)s"
            #
            # Subject to use to notify about multiple messages from one or more users in
            # a room which doesn't have a name.
            #messages_from_person: "%(messages_from_person)s"
            #
            # Subject to use to notify about multiple messages in a room which has a
            # name.
            #messages_in_room: "%(messages_in_room)s"
            #
            # Subject to use to notify about multiple messages in multiple rooms.
            #messages_in_room_and_others: "%(messages_in_room_and_others)s"
            #
            # Subject to use to notify about multiple messages from multiple persons in
            # multiple rooms. This is similar to the setting above except it's used when
            # the room in which the notification was triggered has no name.
            #messages_from_person_and_others: "%(messages_from_person_and_others)s"
            #
            # Subject to use to notify about an invite to a room which has a name.
            #invite_from_person_to_room: "%(invite_from_person_to_room)s"
            #
            # Subject to use to notify about an invite to a room which doesn't have a
            # name.
            #invite_from_person: "%(invite_from_person)s"

            # Subject for emails related to account administration.
            #
            # On top of the '%%(app)s' placeholder, these one can use the
            # '%%(server_name)s' placeholder, which will be replaced by the value of the
            # 'server_name' setting in your Synapse configuration.
            #
            # Subject to use when sending a password reset email.
            #password_reset: "%(password_reset)s"
            #
            # Subject to use when sending a verification email to assert an address's
            # ownership.
            #email_validation: "%(email_validation)s"
        """
            % DEFAULT_SUBJECTS
        )


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
