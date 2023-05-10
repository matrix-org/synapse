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

from enum import Enum
from typing import TYPE_CHECKING, Dict

from synapse.storage.database import DatabasePool, LoggingDatabaseConnection
from synapse.storage.databases.main import CacheInvalidationWorkerStore
from synapse.types import StrCollection
from synapse.util.caches.descriptors import cached

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ExperimentalFeature(str, Enum):
    """
    Currently supported per-user features
    """

    MSC3026 = "msc3026"
    MSC3881 = "msc3881"
    MSC3967 = "msc3967"


class ExperimentalFeaturesStore(CacheInvalidationWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ) -> None:
        super().__init__(database, db_conn, hs)

    @cached()
    async def list_enabled_features(self, user_id: str) -> StrCollection:
        """
        Checks to see what features are enabled for a given user
        Args:
            user:
                the user to be queried on
        Returns:
            the features currently enabled for the user
        """
        enabled = await self.db_pool.simple_select_list(
            "per_user_experimental_features",
            {"user_id": user_id, "enabled": True},
            ["feature"],
        )

        return [feature["feature"] for feature in enabled]

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

    async def get_feature_enabled(
        self, user_id: str, feature: "ExperimentalFeature"
    ) -> bool:
        """
        Checks to see if a given feature is enabled for the user

        Args:
            user_id: the user to be queried on
            feature: the feature in question
        Returns:
                True if the feature is enabled, False if it is not or if the feature was
                not found.
        """

        # check first if feature is enabled in the config
        if feature == ExperimentalFeature.MSC3026:
            globally_enabled = self.hs.config.experimental.msc3026_enabled
        elif feature == ExperimentalFeature.MSC3881:
            globally_enabled = self.hs.config.experimental.msc3881_enabled
        else:
            globally_enabled = self.hs.config.experimental.msc3967_enabled

        if globally_enabled:
            return globally_enabled

        # if it's not enabled globally, check if it is enabled per-user
        res = await self.db_pool.simple_select_one(
            "per_user_experimental_features",
            {"user_id": user_id, "feature": feature},
            ["enabled"],
            allow_none=True,
        )

        # None and false are treated the same
        db_enabled = bool(res)

        return db_enabled
