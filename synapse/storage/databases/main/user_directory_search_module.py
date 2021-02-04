# -*- coding: utf-8 -*-
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

from typing import TYPE_CHECKING, Tuple

from synapse.storage.engines import BaseDatabaseEngine
from synapse.storage.engines.postgres import PostgresEngine
from synapse.storage.engines.sqlite import Sqlite3Engine

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer


class UserDirectorySearchModule:
    """Allows server admins to provide a Python module that augments the results of a
    user directory search.

    Args:
        hs: The HomeServer object.
    """

    def __init__(self, hs: "HomeServer"):
        # If defined, calls to methods will be redirected to this module instead
        self.custom_module = None

        module = None
        config = None
        if hs.config.user_directory_search_module:
            module, config = hs.config.user_directory_search_module

        if module is not None:
            self.custom_module = module(config=config, module_api=hs.get_module_api(),)

    def get_search_query_ordering(
        self, database_engine_type: BaseDatabaseEngine,
    ) -> Tuple[str, Tuple]:
        """Returns the contents of the ORDER BY section of the user directory search
        query. The full query can be found in UserDirectoryStore.

        Args:
            database_engine_type: The type of database engine that is in use. One of
                those in synapse/storage/engines/*.
                Ex. synapse.storage.engines.PostgresEngine

        Returns:
            A string that can be placed after ORDER BY in order to influence the
            ordering of results from a user directory search.
        """
        if self.custom_module is None or not hasattr(
            self.custom_module, "get_search_query_ordering"
        ):
            if isinstance(database_engine_type, PostgresEngine):
                # We order by rank and then if a user has profile info.
                # This ranking algorithm is hand tweaked for "best" results. Broadly
                # the idea is that a higher weight is given to exact matches.
                # The array of numbers are the weights for the various part of the
                # search: (domain, _, display name, localpart)
                return (
                    """
                    (CASE WHEN d.user_id IS NOT NULL THEN 4.0 ELSE 1.0 END)
                    * (CASE WHEN display_name IS NOT NULL THEN 1.2 ELSE 1.0 END)
                    * (CASE WHEN avatar_url IS NOT NULL THEN 1.2 ELSE 1.0 END)
                    * (
                        3 * ts_rank_cd(
                            '{0.1, 0.1, 0.9, 1.0}',
                            vector,
                            to_tsquery('simple', ?),
                            8
                        )
                        + ts_rank_cd(
                            '{0.1, 0.1, 0.9, 1.0}',
                            vector,
                            to_tsquery('simple', ?),
                            8
                        )
                    )
                    DESC,
                    display_name IS NULL,
                    avatar_url IS NULL
                """,
                    (),
                )
            elif isinstance(database_engine_type, Sqlite3Engine):
                # We order by rank and then if a user has profile info.
                return (
                    """
                    rank(matchinfo(user_directory_search)) DESC,
                    display_name IS NULL,
                    avatar_url IS NULL
                """,
                    (),
                )
            else:
                raise Exception("Received an unrecognised database engine")

        return self.custom_module.get_search_query_ordering(database_engine_type)
