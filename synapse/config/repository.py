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
    def __init__(self, args):
        super(ContentRepositoryConfig, self).__init__(args)
        self.max_upload_size = self.parse_size(args.max_upload_size)
        self.max_image_pixels = self.parse_size(args.max_image_pixels)
        self.media_store_path = self.ensure_directory(args.media_store_path)

    def parse_size(self, string):
        sizes = {"K": 1024, "M": 1024 * 1024}
        size = 1
        suffix = string[-1]
        if suffix in sizes:
            string = string[:-1]
            size = sizes[suffix]
        return int(string) * size

    @classmethod
    def add_arguments(cls, parser):
        super(ContentRepositoryConfig, cls).add_arguments(parser)
        db_group = parser.add_argument_group("content_repository")
        db_group.add_argument(
            "--max-upload-size", default="10M"
        )
        db_group.add_argument(
            "--media-store-path", default=cls.default_path("media_store")
        )
        db_group.add_argument(
            "--max-image-pixels", default="32M",
            help="Maximum number of pixels that will be thumbnailed"
        )
