# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from _base import SQLBaseStore


class MediaRepositoryStore(SQLBaseStore):
    """Persistence for attachments and avatars"""

    def get_default_thumbnails(self, top_level_type, sub_type):
        return []

    def get_local_media(self, media_id):
        """Get the metadata for a local piece of media
        Returns:
            None if the meia_id doesn't exist.
        """
        return self._simple_select_one(
            "local_media_repository",
            {"media_id": media_id},
            ("media_type", "media_length", "upload_name", "created_ts"),
            allow_none=True,
        )

    def store_local_media(self, media_id, media_type, time_now_ms, upload_name,
                          media_length, user_id):
        return self._simple_insert(
            "local_media_repository",
            {
                "media_id": media_id,
                "media_type": media_type,
                "created_ts": time_now_ms,
                "upload_name": upload_name,
                "media_length": media_length,
                "user_id": user_id.to_string(),
            }
        )

    def get_local_media_thumbnails(self, media_id):
        return self._simple_select_list(
            "local_media_repository_thumbnails",
            {"media_id": media_id},
            (
                "thumbnail_width", "thumbnail_height", "thumbnail_method",
                "thumbnail_type", "thumbnail_length",
            )
        )

    def store_local_thumbnail(self, media_id, thumbnail_width,
                              thumbnail_height, thumbnail_type,
                              thumbnail_method, thumbnail_length):
        return self._simple_insert(
            "local_media_repository_thumbnails",
            {
                "media_id": media_id,
                "thumbnail_width": thumbnail_width,
                "thumbnail_height": thumbnail_height,
                "thumbnail_method": thumbnail_method,
                "thumbnail_type": thumbnail_type,
                "thumbnail_length": thumbnail_length,
            }
        )

    def get_cached_remote_media(self, origin, media_id):
        return self._simple_select_one(
            "remote_media_cache",
            {"media_origin": origin, "media_id": media_id},
            (
                "media_type", "media_length", "upload_name", "created_ts",
                "filesystem_id",
            ),
            allow_none=True,
        )

    def store_cached_remote_media(self, origin, media_id, media_type,
                                  media_length, time_now_ms, upload_name,
                                  filesystem_id):
        return self._simple_insert(
            "remote_media_cache",
            {
                "media_origin": origin,
                "media_id": media_id,
                "media_type": media_type,
                "media_length": media_length,
                "created_ts": time_now_ms,
                "upload_name": upload_name,
                "filesystem_id": filesystem_id,
            }
        )

    def get_remote_media_thumbnails(self, origin, media_id):
        return self._simple_select_list(
            "remote_media_cache_thumbnails",
            {"media_origin": origin, "media_id": media_id},
            (
                "thumbnail_width", "thumbnail_height", "thumbnail_method",
                "thumbnail_type", "thumbnail_length", "filesystem_id",
            )
        )

    def store_remote_media_thumbnail(self, origin, media_id, filesystem_id,
                                     thumbnail_width, thumbnail_height,
                                     thumbnail_type, thumbnail_method,
                                     thumbnail_length):
        return self._simple_insert(
            "remote_media_cache_thumbnails",
            {
                "media_origin": origin,
                "media_id": media_id,
                "thumbnail_width": thumbnail_width,
                "thumbnail_height": thumbnail_height,
                "thumbnail_method": thumbnail_method,
                "thumbnail_type": thumbnail_type,
                "thumbnail_length": thumbnail_length,
                "filesystem_id": filesystem_id,
            }
        )
