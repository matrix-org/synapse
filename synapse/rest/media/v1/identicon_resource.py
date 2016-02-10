# Copyright 2015, 2016 OpenMarket Ltd
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

from pydenticon import Generator
from twisted.web.resource import Resource

FOREGROUND = [
    "rgb(45,79,255)",
    "rgb(254,180,44)",
    "rgb(226,121,234)",
    "rgb(30,179,253)",
    "rgb(232,77,65)",
    "rgb(49,203,115)",
    "rgb(141,69,170)"
]

BACKGROUND = "rgb(224,224,224)"
SIZE = 5


class IdenticonResource(Resource):
    isLeaf = True

    def __init__(self):
        Resource.__init__(self)
        self.generator = Generator(
            SIZE, SIZE, foreground=FOREGROUND, background=BACKGROUND,
        )

    def generate_identicon(self, name, width, height):
        v_padding = width % SIZE
        h_padding = height % SIZE
        top_padding = v_padding // 2
        left_padding = h_padding // 2
        bottom_padding = v_padding - top_padding
        right_padding = h_padding - left_padding
        width -= v_padding
        height -= h_padding
        padding = (top_padding, bottom_padding, left_padding, right_padding)
        identicon = self.generator.generate(
            name, width, height, padding=padding
        )
        return identicon

    def render_GET(self, request):
        name = "/".join(request.postpath)
        width = int(request.args.get("width", [96])[0])
        height = int(request.args.get("height", [96])[0])
        identicon_bytes = self.generate_identicon(name, width, height)
        request.setHeader(b"Content-Type", b"image/png")
        request.setHeader(
            b"Cache-Control", b"public,max-age=86400,s-maxage=86400"
        )
        return identicon_bytes
