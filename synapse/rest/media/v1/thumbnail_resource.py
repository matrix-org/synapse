# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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


import logging

from synapse.api.errors import SynapseError
from synapse.http.server import DirectServeJsonResource, set_cors_headers
from synapse.http.servlet import parse_integer, parse_string

from ._base import (
    FileInfo,
    parse_media_id,
    respond_404,
    respond_with_file,
    respond_with_responder,
)

logger = logging.getLogger(__name__)


class ThumbnailResource(DirectServeJsonResource):
    isLeaf = True

    def __init__(self, hs, media_repo, media_storage):
        super().__init__()

        self.store = hs.get_datastore()
        self.media_repo = media_repo
        self.media_storage = media_storage
        self.dynamic_thumbnails = hs.config.dynamic_thumbnails
        self.server_name = hs.hostname

    async def _async_render_GET(self, request):
        set_cors_headers(request)
        server_name, media_id, _ = parse_media_id(request)
        width = parse_integer(request, "width", required=True)
        height = parse_integer(request, "height", required=True)
        method = parse_string(request, "method", "scale")
        m_type = parse_string(request, "type", "image/png")

        if server_name == self.server_name:
            if self.dynamic_thumbnails:
                await self._select_or_generate_local_thumbnail(
                    request, media_id, width, height, method, m_type
                )
            else:
                await self._respond_local_thumbnail(
                    request, media_id, width, height, method, m_type
                )
            self.media_repo.mark_recently_accessed(None, media_id)
        else:
            if self.dynamic_thumbnails:
                await self._select_or_generate_remote_thumbnail(
                    request, server_name, media_id, width, height, method, m_type
                )
            else:
                await self._respond_remote_thumbnail(
                    request, server_name, media_id, width, height, method, m_type
                )
            self.media_repo.mark_recently_accessed(server_name, media_id)

    async def _respond_local_thumbnail(
        self, request, media_id, width, height, method, m_type
    ):
        media_info = await self.store.get_local_media(media_id)

        if not media_info:
            respond_404(request)
            return
        if media_info["quarantined_by"]:
            logger.info("Media is quarantined")
            respond_404(request)
            return

        thumbnail_infos = await self.store.get_local_media_thumbnails(media_id)

        if thumbnail_infos:
            thumbnail_info = self._select_thumbnail(
                width, height, method, m_type, thumbnail_infos
            )

            file_info = FileInfo(
                server_name=None,
                file_id=media_id,
                url_cache=media_info["url_cache"],
                thumbnail=True,
                thumbnail_width=thumbnail_info["thumbnail_width"],
                thumbnail_height=thumbnail_info["thumbnail_height"],
                thumbnail_type=thumbnail_info["thumbnail_type"],
                thumbnail_method=thumbnail_info["thumbnail_method"],
            )

            t_type = file_info.thumbnail_type
            t_length = thumbnail_info["thumbnail_length"]

            responder = await self.media_storage.fetch_media(file_info)
            await respond_with_responder(request, responder, t_type, t_length)
        else:
            logger.info("Couldn't find any generated thumbnails")
            respond_404(request)

    async def _select_or_generate_local_thumbnail(
        self,
        request,
        media_id,
        desired_width,
        desired_height,
        desired_method,
        desired_type,
    ):
        media_info = await self.store.get_local_media(media_id)

        if not media_info:
            respond_404(request)
            return
        if media_info["quarantined_by"]:
            logger.info("Media is quarantined")
            respond_404(request)
            return

        thumbnail_infos = await self.store.get_local_media_thumbnails(media_id)
        for info in thumbnail_infos:
            t_w = info["thumbnail_width"] == desired_width
            t_h = info["thumbnail_height"] == desired_height
            t_method = info["thumbnail_method"] == desired_method
            t_type = info["thumbnail_type"] == desired_type

            if t_w and t_h and t_method and t_type:
                file_info = FileInfo(
                    server_name=None,
                    file_id=media_id,
                    url_cache=media_info["url_cache"],
                    thumbnail=True,
                    thumbnail_width=info["thumbnail_width"],
                    thumbnail_height=info["thumbnail_height"],
                    thumbnail_type=info["thumbnail_type"],
                    thumbnail_method=info["thumbnail_method"],
                )

                t_type = file_info.thumbnail_type
                t_length = info["thumbnail_length"]

                responder = await self.media_storage.fetch_media(file_info)
                if responder:
                    await respond_with_responder(request, responder, t_type, t_length)
                    return

        logger.debug("We don't have a thumbnail of that size. Generating")

        # Okay, so we generate one.
        file_path = await self.media_repo.generate_local_exact_thumbnail(
            media_id,
            desired_width,
            desired_height,
            desired_method,
            desired_type,
            url_cache=media_info["url_cache"],
        )

        if file_path:
            await respond_with_file(request, desired_type, file_path)
        else:
            logger.warning("Failed to generate thumbnail")
            raise SynapseError(400, "Failed to generate thumbnail.")

    async def _select_or_generate_remote_thumbnail(
        self,
        request,
        server_name,
        media_id,
        desired_width,
        desired_height,
        desired_method,
        desired_type,
    ):
        media_info = await self.media_repo.get_remote_media_info(server_name, media_id)

        thumbnail_infos = await self.store.get_remote_media_thumbnails(
            server_name, media_id
        )

        file_id = media_info["filesystem_id"]

        for info in thumbnail_infos:
            t_w = info["thumbnail_width"] == desired_width
            t_h = info["thumbnail_height"] == desired_height
            t_method = info["thumbnail_method"] == desired_method
            t_type = info["thumbnail_type"] == desired_type

            if t_w and t_h and t_method and t_type:
                file_info = FileInfo(
                    server_name=server_name,
                    file_id=media_info["filesystem_id"],
                    thumbnail=True,
                    thumbnail_width=info["thumbnail_width"],
                    thumbnail_height=info["thumbnail_height"],
                    thumbnail_type=info["thumbnail_type"],
                    thumbnail_method=info["thumbnail_method"],
                )

                t_type = file_info.thumbnail_type
                t_length = info["thumbnail_length"]

                responder = await self.media_storage.fetch_media(file_info)
                if responder:
                    await respond_with_responder(request, responder, t_type, t_length)
                    return

        logger.debug("We don't have a thumbnail of that size. Generating")

        # Okay, so we generate one.
        file_path = await self.media_repo.generate_remote_exact_thumbnail(
            server_name,
            file_id,
            media_id,
            desired_width,
            desired_height,
            desired_method,
            desired_type,
        )

        if file_path:
            await respond_with_file(request, desired_type, file_path)
        else:
            logger.warning("Failed to generate thumbnail")
            raise SynapseError(400, "Failed to generate thumbnail.")

    async def _respond_remote_thumbnail(
        self, request, server_name, media_id, width, height, method, m_type
    ):
        # TODO: Don't download the whole remote file
        # We should proxy the thumbnail from the remote server instead of
        # downloading the remote file and generating our own thumbnails.
        media_info = await self.media_repo.get_remote_media_info(server_name, media_id)

        thumbnail_infos = await self.store.get_remote_media_thumbnails(
            server_name, media_id
        )

        if thumbnail_infos:
            thumbnail_info = self._select_thumbnail(
                width, height, method, m_type, thumbnail_infos
            )
            file_info = FileInfo(
                server_name=server_name,
                file_id=media_info["filesystem_id"],
                thumbnail=True,
                thumbnail_width=thumbnail_info["thumbnail_width"],
                thumbnail_height=thumbnail_info["thumbnail_height"],
                thumbnail_type=thumbnail_info["thumbnail_type"],
                thumbnail_method=thumbnail_info["thumbnail_method"],
            )

            t_type = file_info.thumbnail_type
            t_length = thumbnail_info["thumbnail_length"]

            responder = await self.media_storage.fetch_media(file_info)
            await respond_with_responder(request, responder, t_type, t_length)
        else:
            logger.info("Failed to find any generated thumbnails")
            respond_404(request)

    def _select_thumbnail(
        self,
        desired_width,
        desired_height,
        desired_method,
        desired_type,
        thumbnail_infos,
    ):
        d_w = desired_width
        d_h = desired_height

        if desired_method.lower() == "crop":
            crop_info_list = []
            crop_info_list2 = []
            for info in thumbnail_infos:
                t_w = info["thumbnail_width"]
                t_h = info["thumbnail_height"]
                t_method = info["thumbnail_method"]
                if t_method == "crop":
                    aspect_quality = abs(d_w * t_h - d_h * t_w)
                    min_quality = 0 if d_w <= t_w and d_h <= t_h else 1
                    size_quality = abs((d_w - t_w) * (d_h - t_h))
                    type_quality = desired_type != info["thumbnail_type"]
                    length_quality = info["thumbnail_length"]
                    if t_w >= d_w or t_h >= d_h:
                        crop_info_list.append(
                            (
                                aspect_quality,
                                min_quality,
                                size_quality,
                                type_quality,
                                length_quality,
                                info,
                            )
                        )
                    else:
                        crop_info_list2.append(
                            (
                                aspect_quality,
                                min_quality,
                                size_quality,
                                type_quality,
                                length_quality,
                                info,
                            )
                        )
            if crop_info_list:
                return min(crop_info_list)[-1]
            else:
                return min(crop_info_list2)[-1]
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
                    info_list.append((size_quality, type_quality, length_quality, info))
                elif t_method == "scale":
                    info_list2.append(
                        (size_quality, type_quality, length_quality, info)
                    )
            if info_list:
                return min(info_list)[-1]
            else:
                return min(info_list2)[-1]
