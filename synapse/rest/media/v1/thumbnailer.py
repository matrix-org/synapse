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

import PIL.Image as Image
from io import BytesIO

import logging

logger = logging.getLogger(__name__)


class Thumbnailer(object):

    FORMATS = {
        "image/jpeg": "JPEG",
        "image/png": "PNG",
    }

    def __init__(self, input_path):
        self.image = Image.open(input_path)
        self.width, self.height = self.image.size

    def aspect(self, max_width, max_height):
        """Calculate the largest size that preserves aspect ratio which
        fits within the given rectangle::

            (w_in / h_in) = (w_out / h_out)
            w_out = min(w_max, h_max * (w_in / h_in))
            h_out = min(h_max, w_max * (h_in / w_in))

        Args:
            max_width: The largest possible width.
            max_height: The larget possible height.
        """

        if max_width * self.height < max_height * self.width:
            return (max_width, (max_width * self.height) // self.width)
        else:
            return ((max_height * self.width) // self.height, max_height)

    def scale(self, output_path, width, height, output_type):
        """Rescales the image to the given dimensions"""
        scaled = self.image.resize((width, height), Image.ANTIALIAS)
        return self.save_image(scaled, output_type, output_path)

    def crop(self, output_path, width, height, output_type):
        """Rescales and crops the image to the given dimensions preserving
        aspect::
            (w_in / h_in) = (w_scaled / h_scaled)
            w_scaled = max(w_out, h_out * (w_in / h_in))
            h_scaled = max(h_out, w_out * (h_in / w_in))

        Args:
            max_width: The largest possible width.
            max_height: The larget possible height.
        """
        if width * self.height > height * self.width:
            scaled_height = (width * self.height) // self.width
            scaled_image = self.image.resize(
                (width, scaled_height), Image.ANTIALIAS
            )
            crop_top = (scaled_height - height) // 2
            crop_bottom = height + crop_top
            cropped = scaled_image.crop((0, crop_top, width, crop_bottom))
        else:
            scaled_width = (height * self.width) // self.height
            scaled_image = self.image.resize(
                (scaled_width, height), Image.ANTIALIAS
            )
            crop_left = (scaled_width - width) // 2
            crop_right = width + crop_left
            cropped = scaled_image.crop((crop_left, 0, crop_right, height))
        return self.save_image(cropped, output_type, output_path)

    def save_image(self, output_image, output_type, output_path):
        output_bytes_io = BytesIO()
        output_image.save(output_bytes_io, self.FORMATS[output_type], quality=80)
        output_bytes = output_bytes_io.getvalue()
        with open(output_path, "wb") as output_file:
            output_file.write(output_bytes)
        logger.info("Stored thumbnail in file %r", output_path)
        return len(output_bytes)
