# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import Any

from synapse.types import JsonDict

from ._base import Config


class AuthConfig(Config):
    """Password and login configuration"""

    section = "auth"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        password_config = config.get("password_config", {})
        if password_config is None:
            password_config = {}

        passwords_enabled = password_config.get("enabled", True)
        # 'only_for_reauth' allows users who have previously set a password to use it,
        # even though passwords would otherwise be disabled.
        passwords_for_reauth_only = passwords_enabled == "only_for_reauth"

        self.password_enabled_for_login = (
            passwords_enabled and not passwords_for_reauth_only
        )
        self.password_enabled_for_reauth = (
            passwords_for_reauth_only or passwords_enabled
        )

        self.password_localdb_enabled = password_config.get("localdb_enabled", True)
        self.password_pepper = password_config.get("pepper", "")

        # Password policy
        self.password_policy = password_config.get("policy") or {}
        self.password_policy_enabled = self.password_policy.get("enabled", False)

        # User-interactive authentication
        ui_auth = config.get("ui_auth") or {}
        self.ui_auth_session_timeout = self.parse_duration(
            ui_auth.get("session_timeout", 0)
        )
