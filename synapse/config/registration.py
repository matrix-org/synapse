# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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
import argparse
from typing import Any, Dict, Optional

from synapse.api.constants import RoomCreationPreset
from synapse.config._base import Config, ConfigError, read_file
from synapse.types import JsonDict, RoomAlias, UserID
from synapse.util.stringutils import random_string_with_symbols, strtobool

NO_EMAIL_DELEGATE_ERROR = """\
Delegation of email verification to an identity server is no longer supported. To
continue to allow users to add email addresses to their accounts, and use them for
password resets, configure Synapse with an SMTP server via the `email` setting, and
remove `account_threepid_delegates.email`.
"""

CONFLICTING_SHARED_SECRET_OPTS_ERROR = """\
You have configured both `registration_shared_secret` and
`registration_shared_secret_path`. These are mutually incompatible.
"""


class RegistrationConfig(Config):
    section = "registration"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.enable_registration = strtobool(
            str(config.get("enable_registration", False))
        )
        if "disable_registration" in config:
            self.enable_registration = not strtobool(
                str(config["disable_registration"])
            )

        self.enable_registration_without_verification = strtobool(
            str(config.get("enable_registration_without_verification", False))
        )

        self.registrations_require_3pid = config.get("registrations_require_3pid", [])
        self.allowed_local_3pids = config.get("allowed_local_3pids", [])
        self.enable_3pid_lookup = config.get("enable_3pid_lookup", True)
        self.registration_requires_token = config.get(
            "registration_requires_token", False
        )
        self.enable_registration_token_3pid_bypass = config.get(
            "enable_registration_token_3pid_bypass", False
        )

        # read the shared secret, either inline or from an external file
        self.registration_shared_secret = config.get("registration_shared_secret")
        registration_shared_secret_path = config.get("registration_shared_secret_path")
        if registration_shared_secret_path:
            if self.registration_shared_secret:
                raise ConfigError(CONFLICTING_SHARED_SECRET_OPTS_ERROR)
            self.registration_shared_secret = read_file(
                registration_shared_secret_path, ("registration_shared_secret_path",)
            ).strip()

        self.bcrypt_rounds = config.get("bcrypt_rounds", 12)

        account_threepid_delegates = config.get("account_threepid_delegates") or {}
        if "email" in account_threepid_delegates:
            raise ConfigError(NO_EMAIL_DELEGATE_ERROR)
        self.account_threepid_delegate_msisdn = account_threepid_delegates.get("msisdn")
        self.default_identity_server = config.get("default_identity_server")
        self.allow_guest_access = config.get("allow_guest_access", False)

        if config.get("invite_3pid_guest", False):
            raise ConfigError("invite_3pid_guest is no longer supported")

        self.auto_join_rooms = config.get("auto_join_rooms", [])
        for room_alias in self.auto_join_rooms:
            if not RoomAlias.is_valid(room_alias):
                raise ConfigError("Invalid auto_join_rooms entry %s" % (room_alias,))

        # Options for creating auto-join rooms if they do not exist yet.
        self.autocreate_auto_join_rooms = config.get("autocreate_auto_join_rooms", True)
        self.autocreate_auto_join_rooms_federated = config.get(
            "autocreate_auto_join_rooms_federated", True
        )
        self.autocreate_auto_join_room_preset = (
            config.get("autocreate_auto_join_room_preset")
            or RoomCreationPreset.PUBLIC_CHAT
        )
        self.auto_join_room_requires_invite = self.autocreate_auto_join_room_preset in {
            RoomCreationPreset.PRIVATE_CHAT,
            RoomCreationPreset.TRUSTED_PRIVATE_CHAT,
        }

        # Pull the creator/inviter from the configuration, this gets used to
        # send invites for invite-only rooms.
        mxid_localpart = config.get("auto_join_mxid_localpart")
        self.auto_join_user_id = None
        if mxid_localpart:
            # Convert the localpart to a full mxid.
            self.auto_join_user_id = UserID(
                mxid_localpart, self.root.server.server_name
            ).to_string()

        if self.autocreate_auto_join_rooms:
            # Ensure the preset is a known value.
            if self.autocreate_auto_join_room_preset not in {
                RoomCreationPreset.PUBLIC_CHAT,
                RoomCreationPreset.PRIVATE_CHAT,
                RoomCreationPreset.TRUSTED_PRIVATE_CHAT,
            }:
                raise ConfigError("Invalid value for autocreate_auto_join_room_preset")
            # If the preset requires invitations to be sent, ensure there's a
            # configured user to send them from.
            if self.auto_join_room_requires_invite:
                if not mxid_localpart:
                    raise ConfigError(
                        "The configuration option `auto_join_mxid_localpart` is required if "
                        "`autocreate_auto_join_room_preset` is set to private_chat or trusted_private_chat, such that "
                        "Synapse knows who to send invitations from. Please "
                        "configure `auto_join_mxid_localpart`."
                    )

        self.auto_join_rooms_for_guests = config.get("auto_join_rooms_for_guests", True)

        self.enable_set_displayname = config.get("enable_set_displayname", True)
        self.enable_set_avatar_url = config.get("enable_set_avatar_url", True)
        self.enable_3pid_changes = config.get("enable_3pid_changes", True)

        self.disable_msisdn_registration = config.get(
            "disable_msisdn_registration", False
        )

        session_lifetime = config.get("session_lifetime")
        if session_lifetime is not None:
            session_lifetime = self.parse_duration(session_lifetime)
        self.session_lifetime = session_lifetime

        # The `refreshable_access_token_lifetime` applies for tokens that can be renewed
        # using a refresh token, as per MSC2918.
        # If it is `None`, the refresh token mechanism is disabled.
        refreshable_access_token_lifetime = config.get(
            "refreshable_access_token_lifetime",
            "5m",
        )
        if refreshable_access_token_lifetime is not None:
            refreshable_access_token_lifetime = self.parse_duration(
                refreshable_access_token_lifetime
            )
        self.refreshable_access_token_lifetime: Optional[
            int
        ] = refreshable_access_token_lifetime

        if (
            self.session_lifetime is not None
            and "refreshable_access_token_lifetime" in config
        ):
            if self.session_lifetime < self.refreshable_access_token_lifetime:
                raise ConfigError(
                    "Both `session_lifetime` and `refreshable_access_token_lifetime` "
                    "configuration options have been set, but `refreshable_access_token_lifetime` "
                    " exceeds `session_lifetime`!"
                )

        # The `nonrefreshable_access_token_lifetime` applies for tokens that can NOT be
        # refreshed using a refresh token.
        # If it is None, then these tokens last for the entire length of the session,
        # which is infinite by default.
        # The intention behind this configuration option is to help with requiring
        # all clients to use refresh tokens, if the homeserver administrator requires.
        nonrefreshable_access_token_lifetime = config.get(
            "nonrefreshable_access_token_lifetime",
            None,
        )
        if nonrefreshable_access_token_lifetime is not None:
            nonrefreshable_access_token_lifetime = self.parse_duration(
                nonrefreshable_access_token_lifetime
            )
        self.nonrefreshable_access_token_lifetime = nonrefreshable_access_token_lifetime

        if (
            self.session_lifetime is not None
            and self.nonrefreshable_access_token_lifetime is not None
        ):
            if self.session_lifetime < self.nonrefreshable_access_token_lifetime:
                raise ConfigError(
                    "Both `session_lifetime` and `nonrefreshable_access_token_lifetime` "
                    "configuration options have been set, but `nonrefreshable_access_token_lifetime` "
                    " exceeds `session_lifetime`!"
                )

        refresh_token_lifetime = config.get("refresh_token_lifetime")
        if refresh_token_lifetime is not None:
            refresh_token_lifetime = self.parse_duration(refresh_token_lifetime)
        self.refresh_token_lifetime: Optional[int] = refresh_token_lifetime

        if (
            self.session_lifetime is not None
            and self.refresh_token_lifetime is not None
        ):
            if self.session_lifetime < self.refresh_token_lifetime:
                raise ConfigError(
                    "Both `session_lifetime` and `refresh_token_lifetime` "
                    "configuration options have been set, but `refresh_token_lifetime` "
                    " exceeds `session_lifetime`!"
                )

        # The fallback template used for authenticating using a registration token
        self.registration_token_template = self.read_template("registration_token.html")

        # The success template used during fallback auth.
        self.fallback_success_template = self.read_template("auth_success.html")

        self.inhibit_user_in_use_error = config.get("inhibit_user_in_use_error", False)

    def generate_config_section(
        self, generate_secrets: bool = False, **kwargs: Any
    ) -> str:
        if generate_secrets:
            registration_shared_secret = 'registration_shared_secret: "%s"' % (
                random_string_with_symbols(50),
            )
            return registration_shared_secret
        else:
            return ""

    def generate_files(self, config: Dict[str, Any], config_dir_path: str) -> None:
        # if 'registration_shared_secret_path' is specified, and the target file
        # does not exist, generate it.
        registration_shared_secret_path = config.get("registration_shared_secret_path")
        if registration_shared_secret_path and not self.path_exists(
            registration_shared_secret_path
        ):
            print(
                "Generating registration shared secret file "
                + registration_shared_secret_path
            )
            secret = random_string_with_symbols(50)
            with open(registration_shared_secret_path, "w") as f:
                f.write(f"{secret}\n")

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        reg_group = parser.add_argument_group("registration")
        reg_group.add_argument(
            "--enable-registration",
            action="store_true",
            default=None,
            help="Enable registration for new users.",
        )

    def read_arguments(self, args: argparse.Namespace) -> None:
        if args.enable_registration is not None:
            self.enable_registration = strtobool(str(args.enable_registration))
