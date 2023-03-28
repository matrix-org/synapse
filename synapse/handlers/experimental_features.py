# Copyright 2023 The Matrix.org Foundation C.I.C
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


from typing import TYPE_CHECKING, Tuple

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ExperimentalFeaturesHandler:
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main

    async def get_feature_enabled(self, user: str, feature: str) -> bool:
        """
        Determine whether a given feature is enabled for the user.
        Args:
            user:
                the user in question
            feature:
                the feature to determine is enabled
        Returns:
                True if the feature is enabled, False if not
        """
        return await self.store.get_feature_enabled(user, feature)

    async def set_feature_for_user(
        self, user: str, feature: str, enabled: bool
    ) -> Tuple[str, str, bool]:
        """
        Set a feature to be enabled/disabled for a given user
        Args:
            user:
                the user in question
            feature:
                the feature to set
            enabled:
                True to enable, False to disable
        Returns:
                a tuple of the user, the feature, and a bool indicating whether the feature is
                enabled
        """
        return await self.store.set_feature_for_user(user, feature, enabled)
