# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

from synapse.storage._base import SQLBaseStore
from synapse.storage.database import DatabasePool

BG_UPDATE_REMOVE_MEDIA_REPO_INDEX_WITHOUT_METHOD = (
    "media_repository_drop_index_wo_method"
)
BG_UPDATE_REMOVE_MEDIA_REPO_INDEX_WITHOUT_METHOD_2 = (
    "media_repository_drop_index_wo_method_2"
)


class MediaSortOrder(Enum):
    """
    Enum to define the sorting method used when returning media with
    get_local_media_by_user_paginate
    """

    MEDIA_ID = "media_id"
    UPLOAD_NAME = "upload_name"
    CREATED_TS = "created_ts"
    LAST_ACCESS_TS = "last_access_ts"
    MEDIA_LENGTH = "media_length"
    MEDIA_TYPE = "media_type"
    QUARANTINED_BY = "quarantined_by"
    SAFE_FROM_QUARANTINE = "safe_from_quarantine"


class MediaRepositoryBackgroundUpdateStore(SQLBaseStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_index_update(
            update_name="local_media_repository_url_idx",
            index_name="local_media_repository_url_idx",
            table="local_media_repository",
            columns=["created_ts"],
            where_clause="url_cache IS NOT NULL",
        )

        # The following the updates add the method to the unique constraint of
        # the thumbnail databases. That fixes an issue, where thumbnails of the
        # same resolution, but different methods could overwrite one another.
        # This can happen with custom thumbnail configs or with dynamic thumbnailing.
        self.db_pool.updates.register_background_index_update(
            update_name="local_media_repository_thumbnails_method_idx",
            index_name="local_media_repository_thumbn_media_id_width_height_method_key",
            table="local_media_repository_thumbnails",
            columns=[
                "media_id",
                "thumbnail_width",
                "thumbnail_height",
                "thumbnail_type",
                "thumbnail_method",
            ],
            unique=True,
        )

        self.db_pool.updates.register_background_index_update(
            update_name="remote_media_repository_thumbnails_method_idx",
            index_name="remote_media_repository_thumbn_media_origin_id_width_height_method_key",
            table="remote_media_cache_thumbnails",
            columns=[
                "media_origin",
                "media_id",
                "thumbnail_width",
                "thumbnail_height",
                "thumbnail_type",
                "thumbnail_method",
            ],
            unique=True,
        )

        # the original impl of _drop_media_index_without_method was broken (see
        # https://github.com/matrix-org/synapse/issues/8649), so we replace the original
        # impl with a no-op and run the fixed migration as
        # media_repository_drop_index_wo_method_2.
        self.db_pool.updates.register_noop_background_update(
            BG_UPDATE_REMOVE_MEDIA_REPO_INDEX_WITHOUT_METHOD
        )
        self.db_pool.updates.register_background_update_handler(
            BG_UPDATE_REMOVE_MEDIA_REPO_INDEX_WITHOUT_METHOD_2,
            self._drop_media_index_without_method,
        )

    async def _drop_media_index_without_method(self, progress, batch_size):
        """background update handler which removes the old constraints.

        Note that this is only run on postgres.
        """

        def f(txn):
            txn.execute(
                "ALTER TABLE local_media_repository_thumbnails DROP CONSTRAINT IF EXISTS local_media_repository_thumbn_media_id_thumbnail_width_thum_key"
            )
            txn.execute(
                "ALTER TABLE remote_media_cache_thumbnails DROP CONSTRAINT IF EXISTS remote_media_cache_thumbnails_media_origin_media_id_thumbna_key"
            )

        await self.db_pool.runInteraction("drop_media_indices_without_method", f)
        await self.db_pool.updates._end_background_update(
            BG_UPDATE_REMOVE_MEDIA_REPO_INDEX_WITHOUT_METHOD_2
        )
        return 1


class MediaRepositoryStore(MediaRepositoryBackgroundUpdateStore):
    """Persistence for attachments and avatars"""

    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)
        self.server_name = hs.hostname

    async def get_local_media(self, media_id: str) -> Optional[Dict[str, Any]]:
        """Get the metadata for a local piece of media

        Returns:
            None if the media_id doesn't exist.
        """
        return await self.db_pool.simple_select_one(
            "local_media_repository",
            {"media_id": media_id},
            (
                "media_type",
                "media_length",
                "upload_name",
                "created_ts",
                "quarantined_by",
                "url_cache",
            ),
            allow_none=True,
            desc="get_local_media",
        )

    async def get_local_media_by_user_paginate(
        self,
        start: int,
        limit: int,
        user_id: str,
        order_by: str = MediaSortOrder.CREATED_TS.value,
        direction: str = "f",
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Get a paginated list of metadata for a local piece of media
        which an user_id has uploaded

        Args:
            start: offset in the list
            limit: maximum amount of media_ids to retrieve
            user_id: fully-qualified user id
            order_by: the sort order of the returned list
            direction: sort ascending or descending
        Returns:
            A paginated list of all metadata of user's media,
            plus the total count of all the user's media
        """

        def get_local_media_by_user_paginate_txn(txn):

            # Set ordering
            order_by_column = MediaSortOrder(order_by).value

            if direction == "b":
                order = "DESC"
            else:
                order = "ASC"

            args = [user_id]
            sql = """
                SELECT COUNT(*) as total_media
                FROM local_media_repository
                WHERE user_id = ?
            """
            txn.execute(sql, args)
            count = txn.fetchone()[0]

            sql = """
                SELECT
                    "media_id",
                    "media_type",
                    "media_length",
                    "upload_name",
                    "created_ts",
                    "last_access_ts",
                    "quarantined_by",
                    "safe_from_quarantine"
                FROM local_media_repository
                WHERE user_id = ?
                ORDER BY {order_by_column} {order}, media_id ASC
                LIMIT ? OFFSET ?
            """.format(
                order_by_column=order_by_column,
                order=order,
            )

            args += [limit, start]
            txn.execute(sql, args)
            media = self.db_pool.cursor_to_dict(txn)
            return media, count

        return await self.db_pool.runInteraction(
            "get_local_media_by_user_paginate_txn", get_local_media_by_user_paginate_txn
        )

    async def get_local_media_before(
        self,
        before_ts: int,
        size_gt: int,
        keep_profiles: bool,
    ) -> List[str]:

        # to find files that have never been accessed (last_access_ts IS NULL)
        # compare with `created_ts`
        sql = """
            SELECT media_id
            FROM local_media_repository AS lmr
            WHERE
                ( last_access_ts < ?
                OR ( created_ts < ? AND last_access_ts IS NULL ) )
                AND media_length > ?
        """

        if keep_profiles:
            sql_keep = """
                AND (
                    NOT EXISTS
                        (SELECT 1
                         FROM profiles
                         WHERE profiles.avatar_url = '{media_prefix}' || lmr.media_id)
                    AND NOT EXISTS
                        (SELECT 1
                         FROM groups
                         WHERE groups.avatar_url = '{media_prefix}' || lmr.media_id)
                    AND NOT EXISTS
                        (SELECT 1
                         FROM room_memberships
                         WHERE room_memberships.avatar_url = '{media_prefix}' || lmr.media_id)
                    AND NOT EXISTS
                        (SELECT 1
                         FROM user_directory
                         WHERE user_directory.avatar_url = '{media_prefix}' || lmr.media_id)
                    AND NOT EXISTS
                        (SELECT 1
                         FROM room_stats_state
                         WHERE room_stats_state.avatar = '{media_prefix}' || lmr.media_id)
                )
            """.format(
                media_prefix="mxc://%s/" % (self.server_name,),
            )
            sql += sql_keep

        def _get_local_media_before_txn(txn):
            txn.execute(sql, (before_ts, before_ts, size_gt))
            return [row[0] for row in txn]

        return await self.db_pool.runInteraction(
            "get_local_media_before", _get_local_media_before_txn
        )

    async def store_local_media(
        self,
        media_id,
        media_type,
        time_now_ms,
        upload_name,
        media_length,
        user_id,
        url_cache=None,
    ) -> None:
        await self.db_pool.simple_insert(
            "local_media_repository",
            {
                "media_id": media_id,
                "media_type": media_type,
                "created_ts": time_now_ms,
                "upload_name": upload_name,
                "media_length": media_length,
                "user_id": user_id.to_string(),
                "url_cache": url_cache,
            },
            desc="store_local_media",
        )

    async def mark_local_media_as_safe(self, media_id: str) -> None:
        """Mark a local media as safe from quarantining."""
        await self.db_pool.simple_update_one(
            table="local_media_repository",
            keyvalues={"media_id": media_id},
            updatevalues={"safe_from_quarantine": True},
            desc="mark_local_media_as_safe",
        )

    async def get_url_cache(self, url: str, ts: int) -> Optional[Dict[str, Any]]:
        """Get the media_id and ts for a cached URL as of the given timestamp
        Returns:
            None if the URL isn't cached.
        """

        def get_url_cache_txn(txn):
            # get the most recently cached result (relative to the given ts)
            sql = (
                "SELECT response_code, etag, expires_ts, og, media_id, download_ts"
                " FROM local_media_repository_url_cache"
                " WHERE url = ? AND download_ts <= ?"
                " ORDER BY download_ts DESC LIMIT 1"
            )
            txn.execute(sql, (url, ts))
            row = txn.fetchone()

            if not row:
                # ...or if we've requested a timestamp older than the oldest
                # copy in the cache, return the oldest copy (if any)
                sql = (
                    "SELECT response_code, etag, expires_ts, og, media_id, download_ts"
                    " FROM local_media_repository_url_cache"
                    " WHERE url = ? AND download_ts > ?"
                    " ORDER BY download_ts ASC LIMIT 1"
                )
                txn.execute(sql, (url, ts))
                row = txn.fetchone()

            if not row:
                return None

            return dict(
                zip(
                    (
                        "response_code",
                        "etag",
                        "expires_ts",
                        "og",
                        "media_id",
                        "download_ts",
                    ),
                    row,
                )
            )

        return await self.db_pool.runInteraction("get_url_cache", get_url_cache_txn)

    async def store_url_cache(
        self, url, response_code, etag, expires_ts, og, media_id, download_ts
    ):
        await self.db_pool.simple_insert(
            "local_media_repository_url_cache",
            {
                "url": url,
                "response_code": response_code,
                "etag": etag,
                "expires_ts": expires_ts,
                "og": og,
                "media_id": media_id,
                "download_ts": download_ts,
            },
            desc="store_url_cache",
        )

    async def get_local_media_thumbnails(self, media_id: str) -> List[Dict[str, Any]]:
        return await self.db_pool.simple_select_list(
            "local_media_repository_thumbnails",
            {"media_id": media_id},
            (
                "thumbnail_width",
                "thumbnail_height",
                "thumbnail_method",
                "thumbnail_type",
                "thumbnail_length",
            ),
            desc="get_local_media_thumbnails",
        )

    async def store_local_thumbnail(
        self,
        media_id,
        thumbnail_width,
        thumbnail_height,
        thumbnail_type,
        thumbnail_method,
        thumbnail_length,
    ):
        await self.db_pool.simple_upsert(
            table="local_media_repository_thumbnails",
            keyvalues={
                "media_id": media_id,
                "thumbnail_width": thumbnail_width,
                "thumbnail_height": thumbnail_height,
                "thumbnail_method": thumbnail_method,
                "thumbnail_type": thumbnail_type,
            },
            values={"thumbnail_length": thumbnail_length},
            desc="store_local_thumbnail",
        )

    async def get_cached_remote_media(
        self, origin, media_id: str
    ) -> Optional[Dict[str, Any]]:
        return await self.db_pool.simple_select_one(
            "remote_media_cache",
            {"media_origin": origin, "media_id": media_id},
            (
                "media_type",
                "media_length",
                "upload_name",
                "created_ts",
                "filesystem_id",
                "quarantined_by",
            ),
            allow_none=True,
            desc="get_cached_remote_media",
        )

    async def store_cached_remote_media(
        self,
        origin,
        media_id,
        media_type,
        media_length,
        time_now_ms,
        upload_name,
        filesystem_id,
    ):
        await self.db_pool.simple_insert(
            "remote_media_cache",
            {
                "media_origin": origin,
                "media_id": media_id,
                "media_type": media_type,
                "media_length": media_length,
                "created_ts": time_now_ms,
                "upload_name": upload_name,
                "filesystem_id": filesystem_id,
                "last_access_ts": time_now_ms,
            },
            desc="store_cached_remote_media",
        )

    async def update_cached_last_access_time(
        self,
        local_media: Iterable[str],
        remote_media: Iterable[Tuple[str, str]],
        time_ms: int,
    ):
        """Updates the last access time of the given media

        Args:
            local_media: Set of media_ids
            remote_media: Set of (server_name, media_id)
            time_ms: Current time in milliseconds
        """

        def update_cache_txn(txn):
            sql = (
                "UPDATE remote_media_cache SET last_access_ts = ?"
                " WHERE media_origin = ? AND media_id = ?"
            )

            txn.execute_batch(
                sql,
                (
                    (time_ms, media_origin, media_id)
                    for media_origin, media_id in remote_media
                ),
            )

            sql = (
                "UPDATE local_media_repository SET last_access_ts = ?"
                " WHERE media_id = ?"
            )

            txn.execute_batch(sql, ((time_ms, media_id) for media_id in local_media))

        return await self.db_pool.runInteraction(
            "update_cached_last_access_time", update_cache_txn
        )

    async def get_remote_media_thumbnails(
        self, origin: str, media_id: str
    ) -> List[Dict[str, Any]]:
        return await self.db_pool.simple_select_list(
            "remote_media_cache_thumbnails",
            {"media_origin": origin, "media_id": media_id},
            (
                "thumbnail_width",
                "thumbnail_height",
                "thumbnail_method",
                "thumbnail_type",
                "thumbnail_length",
                "filesystem_id",
            ),
            desc="get_remote_media_thumbnails",
        )

    async def get_remote_media_thumbnail(
        self,
        origin: str,
        media_id: str,
        t_width: int,
        t_height: int,
        t_type: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch the thumbnail info of given width, height and type."""

        return await self.db_pool.simple_select_one(
            table="remote_media_cache_thumbnails",
            keyvalues={
                "media_origin": origin,
                "media_id": media_id,
                "thumbnail_width": t_width,
                "thumbnail_height": t_height,
                "thumbnail_type": t_type,
            },
            retcols=(
                "thumbnail_width",
                "thumbnail_height",
                "thumbnail_method",
                "thumbnail_type",
                "thumbnail_length",
                "filesystem_id",
            ),
            allow_none=True,
            desc="get_remote_media_thumbnail",
        )

    async def store_remote_media_thumbnail(
        self,
        origin,
        media_id,
        filesystem_id,
        thumbnail_width,
        thumbnail_height,
        thumbnail_type,
        thumbnail_method,
        thumbnail_length,
    ):
        await self.db_pool.simple_upsert(
            table="remote_media_cache_thumbnails",
            keyvalues={
                "media_origin": origin,
                "media_id": media_id,
                "thumbnail_width": thumbnail_width,
                "thumbnail_height": thumbnail_height,
                "thumbnail_method": thumbnail_method,
                "thumbnail_type": thumbnail_type,
            },
            values={"thumbnail_length": thumbnail_length},
            insertion_values={"filesystem_id": filesystem_id},
            desc="store_remote_media_thumbnail",
        )

    async def get_remote_media_before(self, before_ts):
        sql = (
            "SELECT media_origin, media_id, filesystem_id"
            " FROM remote_media_cache"
            " WHERE last_access_ts < ?"
        )

        return await self.db_pool.execute(
            "get_remote_media_before", self.db_pool.cursor_to_dict, sql, before_ts
        )

    async def delete_remote_media(self, media_origin: str, media_id: str) -> None:
        def delete_remote_media_txn(txn):
            self.db_pool.simple_delete_txn(
                txn,
                "remote_media_cache",
                keyvalues={"media_origin": media_origin, "media_id": media_id},
            )
            self.db_pool.simple_delete_txn(
                txn,
                "remote_media_cache_thumbnails",
                keyvalues={"media_origin": media_origin, "media_id": media_id},
            )

        await self.db_pool.runInteraction(
            "delete_remote_media", delete_remote_media_txn
        )

    async def get_expired_url_cache(self, now_ts: int) -> List[str]:
        sql = (
            "SELECT media_id FROM local_media_repository_url_cache"
            " WHERE expires_ts < ?"
            " ORDER BY expires_ts ASC"
            " LIMIT 500"
        )

        def _get_expired_url_cache_txn(txn):
            txn.execute(sql, (now_ts,))
            return [row[0] for row in txn]

        return await self.db_pool.runInteraction(
            "get_expired_url_cache", _get_expired_url_cache_txn
        )

    async def delete_url_cache(self, media_ids):
        if len(media_ids) == 0:
            return

        sql = "DELETE FROM local_media_repository_url_cache WHERE media_id = ?"

        def _delete_url_cache_txn(txn):
            txn.execute_batch(sql, [(media_id,) for media_id in media_ids])

        return await self.db_pool.runInteraction(
            "delete_url_cache", _delete_url_cache_txn
        )

    async def get_url_cache_media_before(self, before_ts: int) -> List[str]:
        sql = (
            "SELECT media_id FROM local_media_repository"
            " WHERE created_ts < ? AND url_cache IS NOT NULL"
            " ORDER BY created_ts ASC"
            " LIMIT 500"
        )

        def _get_url_cache_media_before_txn(txn):
            txn.execute(sql, (before_ts,))
            return [row[0] for row in txn]

        return await self.db_pool.runInteraction(
            "get_url_cache_media_before", _get_url_cache_media_before_txn
        )

    async def delete_url_cache_media(self, media_ids):
        if len(media_ids) == 0:
            return

        def _delete_url_cache_media_txn(txn):
            sql = "DELETE FROM local_media_repository WHERE media_id = ?"

            txn.execute_batch(sql, [(media_id,) for media_id in media_ids])

            sql = "DELETE FROM local_media_repository_thumbnails WHERE media_id = ?"

            txn.execute_batch(sql, [(media_id,) for media_id in media_ids])

        return await self.db_pool.runInteraction(
            "delete_url_cache_media", _delete_url_cache_media_txn
        )
