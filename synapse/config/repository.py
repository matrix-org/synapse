# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
import os

class ContentRepositoryConfig(Config):
    def __init__(self, args):
        super(ContentRepositoryConfig, self).__init__(args)
        self.max_upload_size = self.parse_size(args.max_upload_size)

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
            "--max-upload-size", default="1M"
        )
