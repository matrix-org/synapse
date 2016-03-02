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
from collections import namedtuple

ThumbnailRequirement = namedtuple(
    "ThumbnailRequirement", ["width", "height", "method", "media_type"]
)


def parse_thumbnail_requirements(thumbnail_sizes):
    """ Takes a list of dictionaries with "width", "height", and "method" keys
    and creates a map from image media types to the thumbnail size, thumnailing
    method, and thumbnail media type to precalculate

    Args:
        thumbnail_sizes(list): List of dicts with "width", "height", and
            "method" keys
    Returns:
        Dictionary mapping from media type string to list of
        ThumbnailRequirement tuples.
    """
    requirements = {}
    for size in thumbnail_sizes:
        width = size["width"]
        height = size["height"]
        method = size["method"]
        jpeg_thumbnail = ThumbnailRequirement(width, height, method, "image/jpeg")
        png_thumbnail = ThumbnailRequirement(width, height, method, "image/png")
        requirements.setdefault("image/jpeg", []).append(jpeg_thumbnail)
        requirements.setdefault("image/gif", []).append(png_thumbnail)
        requirements.setdefault("image/png", []).append(png_thumbnail)
    return {
        media_type: tuple(thumbnails)
        for media_type, thumbnails in requirements.items()
    }


class ContentRepositoryConfig(Config):
    def read_config(self, config):
        self.max_upload_size = self.parse_size(config["max_upload_size"])
        self.max_image_pixels = self.parse_size(config["max_image_pixels"])
        self.media_store_path = self.ensure_directory(config["media_store_path"])
        self.uploads_path = self.ensure_directory(config["uploads_path"])
        self.dynamic_thumbnails = config["dynamic_thumbnails"]
        self.thumbnail_requirements = parse_thumbnail_requirements(
            config["thumbnail_sizes"]
        )

    def default_config(self, **kwargs):
        media_store = self.default_path("media_store")
        uploads_path = self.default_path("uploads")
        return """
        # Directory where uploaded images and attachments are stored.
        media_store_path: "%(media_store)s"

        # Directory where in-progress uploads are stored.
        uploads_path: "%(uploads_path)s"

        # The largest allowed upload size in bytes
        max_upload_size: "10M"

        # Maximum number of pixels that will be thumbnailed
        max_image_pixels: "32M"

        # Whether to generate new thumbnails on the fly to precisely match
        # the resolution requested by the client. If true then whenever
        # a new resolution is requested by the client the server will
        # generate a new thumbnail. If false the server will pick a thumbnail
        # from a precalcualted list.
        dynamic_thumbnails: false

        # List of thumbnail to precalculate when an image is uploaded.
        thumbnail_sizes:
        - width: 32
          height: 32
          method: crop
        - width: 96
          height: 96
          method: crop
        - width: 320
          height: 240
          method: scale
        - width: 640
          height: 480
          method: scale
        - width: 800
          height: 600
          method: scale
        """ % locals()
