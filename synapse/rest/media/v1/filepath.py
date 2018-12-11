# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

import functools
import os
import re

NEW_FORMAT_ID_RE = re.compile(r"^\d\d\d\d-\d\d-\d\d")


def _wrap_in_base_path(func):
    """Takes a function that returns a relative path and turns it into an
    absolute path based on the location of the primary media store
    """
    @functools.wraps(func)
    def _wrapped(self, *args, **kwargs):
        path = func(self, *args, **kwargs)
        return os.path.join(self.base_path, path)

    return _wrapped


class MediaFilePaths(object):
    """Describes where files are stored on disk.

    Most of the functions have a `*_rel` variant which returns a file path that
    is relative to the base media store path. This is mainly used when we want
    to write to the backup media store (when one is configured)
    """

    def __init__(self, primary_base_path):
        self.base_path = primary_base_path

    def default_thumbnail_rel(self, default_top_level, default_sub_type, width,
                              height, content_type, method):
        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s-%s" % (
            width, height, top_level_type, sub_type, method
        )
        return os.path.join(
            "default_thumbnails", default_top_level,
            default_sub_type, file_name
        )

    default_thumbnail = _wrap_in_base_path(default_thumbnail_rel)

    def local_media_filepath_rel(self, media_id):
        return os.path.join(
            "local_content",
            media_id[0:2], media_id[2:4], media_id[4:]
        )

    local_media_filepath = _wrap_in_base_path(local_media_filepath_rel)

    def local_media_thumbnail_rel(self, media_id, width, height, content_type,
                                  method):
        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s-%s" % (
            width, height, top_level_type, sub_type, method
        )
        return os.path.join(
            "local_thumbnails",
            media_id[0:2], media_id[2:4], media_id[4:],
            file_name
        )

    local_media_thumbnail = _wrap_in_base_path(local_media_thumbnail_rel)

    def remote_media_filepath_rel(self, server_name, file_id):
        return os.path.join(
            "remote_content", server_name,
            file_id[0:2], file_id[2:4], file_id[4:]
        )

    remote_media_filepath = _wrap_in_base_path(remote_media_filepath_rel)

    def remote_media_thumbnail_rel(self, server_name, file_id, width, height,
                                   content_type, method):
        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s" % (width, height, top_level_type, sub_type)
        return os.path.join(
            "remote_thumbnail", server_name,
            file_id[0:2], file_id[2:4], file_id[4:],
            file_name
        )

    remote_media_thumbnail = _wrap_in_base_path(remote_media_thumbnail_rel)

    def remote_media_thumbnail_dir(self, server_name, file_id):
        return os.path.join(
            self.base_path, "remote_thumbnail", server_name,
            file_id[0:2], file_id[2:4], file_id[4:],
        )

    def url_cache_filepath_rel(self, media_id):
        if NEW_FORMAT_ID_RE.match(media_id):
            # Media id is of the form <DATE><RANDOM_STRING>
            # E.g.: 2017-09-28-fsdRDt24DS234dsf
            return os.path.join(
                "url_cache",
                media_id[:10], media_id[11:]
            )
        else:
            return os.path.join(
                "url_cache",
                media_id[0:2], media_id[2:4], media_id[4:],
            )

    url_cache_filepath = _wrap_in_base_path(url_cache_filepath_rel)

    def url_cache_filepath_dirs_to_delete(self, media_id):
        "The dirs to try and remove if we delete the media_id file"
        if NEW_FORMAT_ID_RE.match(media_id):
            return [
                os.path.join(
                    self.base_path, "url_cache",
                    media_id[:10],
                ),
            ]
        else:
            return [
                os.path.join(
                    self.base_path, "url_cache",
                    media_id[0:2], media_id[2:4],
                ),
                os.path.join(
                    self.base_path, "url_cache",
                    media_id[0:2],
                ),
            ]

    def url_cache_thumbnail_rel(self, media_id, width, height, content_type,
                                method):
        # Media id is of the form <DATE><RANDOM_STRING>
        # E.g.: 2017-09-28-fsdRDt24DS234dsf

        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s-%s" % (
            width, height, top_level_type, sub_type, method
        )

        if NEW_FORMAT_ID_RE.match(media_id):
            return os.path.join(
                "url_cache_thumbnails",
                media_id[:10], media_id[11:],
                file_name
            )
        else:
            return os.path.join(
                "url_cache_thumbnails",
                media_id[0:2], media_id[2:4], media_id[4:],
                file_name
            )

    url_cache_thumbnail = _wrap_in_base_path(url_cache_thumbnail_rel)

    def url_cache_thumbnail_directory(self, media_id):
        # Media id is of the form <DATE><RANDOM_STRING>
        # E.g.: 2017-09-28-fsdRDt24DS234dsf

        if NEW_FORMAT_ID_RE.match(media_id):
            return os.path.join(
                self.base_path, "url_cache_thumbnails",
                media_id[:10], media_id[11:],
            )
        else:
            return os.path.join(
                self.base_path, "url_cache_thumbnails",
                media_id[0:2], media_id[2:4], media_id[4:],
            )

    def url_cache_thumbnail_dirs_to_delete(self, media_id):
        "The dirs to try and remove if we delete the media_id thumbnails"
        # Media id is of the form <DATE><RANDOM_STRING>
        # E.g.: 2017-09-28-fsdRDt24DS234dsf
        if NEW_FORMAT_ID_RE.match(media_id):
            return [
                os.path.join(
                    self.base_path, "url_cache_thumbnails",
                    media_id[:10], media_id[11:],
                ),
                os.path.join(
                    self.base_path, "url_cache_thumbnails",
                    media_id[:10],
                ),
            ]
        else:
            return [
                os.path.join(
                    self.base_path, "url_cache_thumbnails",
                    media_id[0:2], media_id[2:4], media_id[4:],
                ),
                os.path.join(
                    self.base_path, "url_cache_thumbnails",
                    media_id[0:2], media_id[2:4],
                ),
                os.path.join(
                    self.base_path, "url_cache_thumbnails",
                    media_id[0:2],
                ),
            ]
