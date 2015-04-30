# -*- coding: utf-8 -*-
# Copyright 2014, 2015 matrix.org
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

from ._base import Config


class ContentRepositoryConfig(Config):
    def read_config(self, config):
        self.max_upload_size = self.parse_size(config["max_upload_size"])
        self.max_image_pixels = self.parse_size(config["max_image_pixels"])
        self.media_store_path = self.ensure_directory(config["media_store_path"])

    def default_config(self, config_dir_path, server_name):
        media_store = self.default_path("media_store")
        return """
        # Directory where uploaded images and attachments are stored.
        media_store_path: "%(media_store)s"

        # The largest allowed upload size in bytes
        max_upload_size: "10M"

        # Maximum number of pixels that will be thumbnailed
        max_image_pixels: "32M"
        """ % locals()
