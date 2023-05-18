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

from typing import Any

from synapse.types import JsonDict

from ._base import Config


class UserDirectoryConfig(Config):
    """User Directory Configuration
    Configuration for the behaviour of the /user_directory API
    """

    section = "userdirectory"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        user_directory_config = config.get("user_directory") or {}
        self.user_directory_search_enabled = user_directory_config.get("enabled", True)
        self.user_directory_search_all_users = user_directory_config.get(
            "search_all_users", False
        )
        self.user_directory_search_prefer_local_users = user_directory_config.get(
            "prefer_local_users", False
        )
