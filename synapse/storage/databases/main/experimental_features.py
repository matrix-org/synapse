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

from typing import TYPE_CHECKING

from black import Tuple

from synapse.api.errors import StoreError
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import DatabasePool, LoggingDatabaseConnection

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ExperimentalFeaturesStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ) -> None:
        super().__init__(database, db_conn, hs)

    async def get_feature_enabled(self, user_id: str, feature: str) -> bool:
        """
        Checks to see if a given feature is enabled for the user
        Args:
            user:
                the user to be queried on
            feature:
                the feature in question
        Returns:
                True if the feature is enabled, False if it is not or if the feature was
                not found.
        """
        enabled = await self.db_pool.simple_select_one(
            "per_user_experimental_features",
            {"user_id": user_id},
            [feature],
            allow_none=True,
        )

        if not enabled or not enabled[feature]:
            return False
        else:
            return True

    async def set_feature_for_user(
        self, user: str, feature: str, enabled: bool
    ) -> Tuple[str, str, bool]:
        """
        Enables or disables a given feature for a given user
        Args:
            user:
                the user for whom to enable/disable a feature
            feature:
                the feature to be enabled/diabled
            enabled:
                True to enable, False to disable
            Returns:
                A tuple of user, feature, and a bool indicating that the feature is enabled
                or disabled
        """
        success = await self.db_pool.simple_upsert(
            "per_user_experimental_features", {"user_id": user}, {feature: enabled}
        )
        if not success:
            raise StoreError(500, "There was a problem setting your feature.")

        return user, feature, enabled
