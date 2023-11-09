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

from typing import TYPE_CHECKING, Dict, FrozenSet, List, Tuple, cast

from synapse.storage.database import DatabasePool, LoggingDatabaseConnection
from synapse.storage.databases.main import CacheInvalidationWorkerStore
from synapse.util.caches.descriptors import cached

if TYPE_CHECKING:
    from synapse.rest.admin.experimental_features import ExperimentalFeature
    from synapse.server import HomeServer


class ExperimentalFeaturesStore(CacheInvalidationWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ) -> None:
        super().__init__(database, db_conn, hs)

    @cached()
    async def list_enabled_features(self, user_id: str) -> FrozenSet[str]:
        """
        Checks to see what features are enabled for a given user
        Args:
            user:
                the user to be queried on
        Returns:
            the features currently enabled for the user
        """
        enabled = cast(
            List[Tuple[str]],
            await self.db_pool.simple_select_list(
                table="per_user_experimental_features",
                keyvalues={"user_id": user_id, "enabled": True},
                retcols=("feature",),
            ),
        )

        return frozenset(feature[0] for feature in enabled)

    async def set_features_for_user(
        self,
        user: str,
        features: Dict["ExperimentalFeature", bool],
    ) -> None:
        """
        Enables or disables features for a given user
        Args:
            user:
                the user for whom to enable/disable the features
            features:
                pairs of features and True/False for whether the feature should be enabled
        """
        for feature, enabled in features.items():
            await self.db_pool.simple_upsert(
                table="per_user_experimental_features",
                keyvalues={"feature": feature, "user_id": user},
                values={"enabled": enabled},
                insertion_values={"user_id": user, "feature": feature},
            )

            await self.invalidate_cache_and_stream("list_enabled_features", (user,))
