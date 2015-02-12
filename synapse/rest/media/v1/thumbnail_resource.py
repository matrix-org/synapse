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


from .base_resource import BaseMediaResource

from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer

import logging

logger = logging.getLogger(__name__)


class ThumbnailResource(BaseMediaResource):
    isLeaf = True

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @BaseMediaResource.catch_errors
    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        server_name, media_id = self._parse_media_id(request)
        width = self._parse_integer(request, "width")
        height = self._parse_integer(request, "height")
        method = self._parse_string(request, "method", "scale")
        m_type = self._parse_string(request, "type", "image/png")

        if server_name == self.server_name:
            yield self._respond_local_thumbnail(
                request, media_id, width, height, method, m_type
            )
        else:
            yield self._respond_remote_thumbnail(
                request, server_name, media_id,
                width, height, method, m_type
            )

    @defer.inlineCallbacks
    def _respond_local_thumbnail(self, request, media_id, width, height,
                                 method, m_type):
        media_info = yield self.store.get_local_media(media_id)

        if not media_info:
            self._respond_404(request)
            return

        thumbnail_infos = yield self.store.get_local_media_thumbnails(media_id)

        if thumbnail_infos:
            thumbnail_info = self._select_thumbnail(
                width, height, method, m_type, thumbnail_infos
            )
            t_width = thumbnail_info["thumbnail_width"]
            t_height = thumbnail_info["thumbnail_height"]
            t_type = thumbnail_info["thumbnail_type"]
            t_method = thumbnail_info["thumbnail_method"]

            file_path = self.filepaths.local_media_thumbnail(
                media_id, t_width, t_height, t_type, t_method,
            )
            yield self._respond_with_file(request, t_type, file_path)

        else:
            yield self._respond_default_thumbnail(
                request, media_info, width, height, method, m_type,
            )

    @defer.inlineCallbacks
    def _respond_remote_thumbnail(self, request, server_name, media_id, width,
                                  height, method, m_type):
        # TODO: Don't download the whole remote file
        # We should proxy the thumbnail from the remote server instead.
        media_info = yield self._get_remote_media(server_name, media_id)

        thumbnail_infos = yield self.store.get_remote_media_thumbnails(
            server_name, media_id,
        )

        if thumbnail_infos:
            thumbnail_info = self._select_thumbnail(
                width, height, method, m_type, thumbnail_infos
            )
            t_width = thumbnail_info["thumbnail_width"]
            t_height = thumbnail_info["thumbnail_height"]
            t_type = thumbnail_info["thumbnail_type"]
            t_method = thumbnail_info["thumbnail_method"]
            file_id = thumbnail_info["filesystem_id"]
            t_length = thumbnail_info["thumbnail_length"]

            file_path = self.filepaths.remote_media_thumbnail(
                server_name, file_id, t_width, t_height, t_type, t_method,
            )
            yield self._respond_with_file(request, t_type, file_path, t_length)
        else:
            yield self._respond_default_thumbnail(
                request, media_info, width, height, method, m_type,
            )

    @defer.inlineCallbacks
    def _respond_default_thumbnail(self, request, media_info, width, height,
                                   method, m_type):
        media_type = media_info["media_type"]
        top_level_type = media_type.split("/")[0]
        sub_type = media_type.split("/")[-1].split(";")[0]
        thumbnail_infos = yield self.store.get_default_thumbnails(
            top_level_type, sub_type,
        )
        if not thumbnail_infos:
            thumbnail_infos = yield self.store.get_default_thumbnails(
                top_level_type, "_default",
            )
        if not thumbnail_infos:
            thumbnail_infos = yield self.store.get_default_thumbnails(
                "_default", "_default",
            )
        if not thumbnail_infos:
            self._respond_404(request)
            return

        thumbnail_info = self._select_thumbnail(
            width, height, "crop", m_type, thumbnail_infos
        )

        t_width = thumbnail_info["thumbnail_width"]
        t_height = thumbnail_info["thumbnail_height"]
        t_type = thumbnail_info["thumbnail_type"]
        t_method = thumbnail_info["thumbnail_method"]
        t_length = thumbnail_info["thumbnail_length"]

        file_path = self.filepaths.default_thumbnail(
            top_level_type, sub_type, t_width, t_height, t_type, t_method,
        )
        yield self.respond_with_file(request, t_type, file_path, t_length)

    def _select_thumbnail(self, desired_width, desired_height, desired_method,
                          desired_type, thumbnail_infos):
        d_w = desired_width
        d_h = desired_height

        if desired_method.lower() == "crop":
            info_list = []
            for info in thumbnail_infos:
                t_w = info["thumbnail_width"]
                t_h = info["thumbnail_height"]
                t_method = info["thumbnail_method"]
                if t_method == "scale" or t_method == "crop":
                    aspect_quality = abs(d_w * t_h - d_h * t_w)
                    size_quality = abs((d_w - t_w) * (d_h - t_h))
                    type_quality = desired_type != info["thumbnail_type"]
                    length_quality = info["thumbnail_length"]
                    info_list.append((
                        aspect_quality, size_quality, type_quality,
                        length_quality, info
                    ))
            if info_list:
                return min(info_list)[-1]
        else:
            info_list = []
            info_list2 = []
            for info in thumbnail_infos:
                t_w = info["thumbnail_width"]
                t_h = info["thumbnail_height"]
                t_method = info["thumbnail_method"]
                size_quality = abs((d_w - t_w) * (d_h - t_h))
                type_quality = desired_type != info["thumbnail_type"]
                length_quality = info["thumbnail_length"]
                if t_method == "scale" and (t_w >= d_w or t_h >= d_h):
                    info_list.append((
                        size_quality, type_quality, length_quality, info
                    ))
                elif t_method == "scale":
                    info_list2.append((
                        size_quality, type_quality, length_quality, info
                    ))
            if info_list:
                return min(info_list)[-1]
            else:
                return min(info_list2)[-1]
