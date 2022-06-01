# Copyright 2018 New Vector Ltd
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

from os import path
from typing import Any, Optional

from synapse.config import ConfigError
from synapse.types import JsonDict

from ._base import Config


class ConsentConfig(Config):

    section = "consent"

    def __init__(self, *args: Any):
        super().__init__(*args)

        self.user_consent_version: Optional[str] = None
        self.user_consent_template_dir: Optional[str] = None
        self.user_consent_server_notice_content: Optional[JsonDict] = None
        self.user_consent_server_notice_to_guests = False
        self.block_events_without_consent_error: Optional[str] = None
        self.user_consent_at_registration = False
        self.user_consent_policy_name = "Privacy Policy"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        consent_config = config.get("user_consent")
        self.terms_template = self.read_template("terms.html")

        if consent_config is None:
            return
        self.user_consent_version = str(consent_config["version"])
        self.user_consent_template_dir = self.abspath(consent_config["template_dir"])
        if not isinstance(self.user_consent_template_dir, str) or not path.isdir(
            self.user_consent_template_dir
        ):
            raise ConfigError(
                "Could not find template directory '%s'"
                % (self.user_consent_template_dir,)
            )
        self.user_consent_server_notice_content = consent_config.get(
            "server_notice_content"
        )
        self.block_events_without_consent_error = consent_config.get(
            "block_events_error"
        )
        self.user_consent_server_notice_to_guests = bool(
            consent_config.get("send_server_notice_to_guests", False)
        )
        self.user_consent_at_registration = bool(
            consent_config.get("require_at_registration", False)
        )
        self.user_consent_policy_name = consent_config.get(
            "policy_name", "Privacy Policy"
        )
