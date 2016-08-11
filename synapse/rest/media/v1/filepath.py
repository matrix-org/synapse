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

import os


class MediaFilePaths(object):

    def __init__(self, base_path):
        self.base_path = base_path

    def default_thumbnail(self, default_top_level, default_sub_type, width,
                          height, content_type, method):
        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s-%s" % (
            width, height, top_level_type, sub_type, method
        )
        return os.path.join(
            self.base_path, "default_thumbnails", default_top_level,
            default_sub_type, file_name
        )

    def local_media_filepath(self, media_id):
        return os.path.join(
            self.base_path, "local_content",
            media_id[0:2], media_id[2:4], media_id[4:]
        )

    def local_media_thumbnail(self, media_id, width, height, content_type,
                              method):
        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s-%s" % (
            width, height, top_level_type, sub_type, method
        )
        return os.path.join(
            self.base_path, "local_thumbnails",
            media_id[0:2], media_id[2:4], media_id[4:],
            file_name
        )

    def remote_media_filepath(self, server_name, file_id):
        return os.path.join(
            self.base_path, "remote_content", server_name,
            file_id[0:2], file_id[2:4], file_id[4:]
        )

    def remote_media_thumbnail(self, server_name, file_id, width, height,
                               content_type, method):
        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s" % (width, height, top_level_type, sub_type)
        return os.path.join(
            self.base_path, "remote_thumbnail", server_name,
            file_id[0:2], file_id[2:4], file_id[4:],
            file_name
        )

    def remote_media_thumbnail_dir(self, server_name, file_id):
        return os.path.join(
            self.base_path, "remote_thumbnail", server_name,
            file_id[0:2], file_id[2:4], file_id[4:],
        )
