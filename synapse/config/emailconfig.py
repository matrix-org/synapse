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
import logging
import os
from enum import Enum
from typing import Any

import attr

from synapse.types import JsonDict

from ._base import Config, ConfigError

logger = logging.getLogger(__name__)

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
    "invite_from_person_to_space": "[%(app)s] %(person)s has invited you to join the %(space)s space on %(app)s...",
    "password_reset": "[%(server_name)s] Password reset",
    "email_validation": "[%(server_name)s] Validate your email",
}

LEGACY_TEMPLATE_DIR_WARNING = """
This server's configuration file is using the deprecated 'template_dir' setting in the
'email' section. Support for this setting has been deprecated and will be removed in a
future version of Synapse. Server admins should instead use the new
'custom_templates_directory' setting documented here:
https://matrix-org.github.io/synapse/latest/templates.html
---------------------------------------------------------------------------------------"""


@attr.s(slots=True, frozen=True, auto_attribs=True)
class EmailSubjectConfig:
    message_from_person_in_room: str
    message_from_person: str
    messages_from_person: str
    messages_in_room: str
    messages_in_room_and_others: str
    messages_from_person_and_others: str
    invite_from_person: str
    invite_from_person_to_room: str
    invite_from_person_to_space: str
    password_reset: str
    email_validation: str


class EmailConfig(Config):
    section = "email"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
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
        self.enable_smtp_tls = email_config.get("enable_tls", True)
        if self.require_transport_security and not self.enable_smtp_tls:
            raise ConfigError(
                "email.require_transport_security requires email.enable_tls to be true"
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
        if template_dir is not None:
            logger.warning(LEGACY_TEMPLATE_DIR_WARNING)

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
            if self.root.registration.account_threepid_delegate_email
            else ThreepidBehaviour.LOCAL
        )

        if config.get("trust_identity_server_for_password_resets"):
            raise ConfigError(
                'The config option "trust_identity_server_for_password_resets" '
                'has been replaced by "account_threepid_delegate". '
                "Please consult the configuration manual at docs/usage/configuration/config_documentation.md for "
                "details and update your config file."
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
                (
                    td
                    for td in (
                        self.root.server.custom_template_directory,
                        template_dir,
                    )
                    if td
                ),  # Filter out template_dir if not provided
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
                [notif_template_html, notif_template_text],
                (
                    td
                    for td in (
                        self.root.server.custom_template_directory,
                        template_dir,
                    )
                    if td
                ),  # Filter out template_dir if not provided
            )

            self.email_notif_for_new_users = email_config.get(
                "notif_for_new_users", True
            )
            self.email_riot_base_url = email_config.get(
                "client_base_url", email_config.get("riot_base_url", None)
            )

        if self.root.account_validity.account_validity_renew_by_email_enabled:
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
                [expiry_template_html, expiry_template_text],
                (
                    td
                    for td in (
                        self.root.server.custom_template_directory,
                        template_dir,
                    )
                    if td
                ),  # Filter out template_dir if not provided
            )

        subjects_config = email_config.get("subjects", {})
        subjects = {}

        for key, default in DEFAULT_SUBJECTS.items():
            subjects[key] = subjects_config.get(key, default)

        self.email_subjects = EmailSubjectConfig(**subjects)

        # The invite client location should be a HTTP(S) URL or None.
        self.invite_client_location = email_config.get("invite_client_location") or None
        if self.invite_client_location:
            if not isinstance(self.invite_client_location, str):
                raise ConfigError(
                    "Config option email.invite_client_location must be type str"
                )
            if not (
                self.invite_client_location.startswith("http://")
                or self.invite_client_location.startswith("https://")
            ):
                raise ConfigError(
                    "Config option email.invite_client_location must be a http or https URL",
                    path=("email", "invite_client_location"),
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
