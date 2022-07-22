# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from synapse.api.errors import Codes, SynapseError, cs_error
from synapse.config.repository import THUMBNAIL_SUPPORTED_MEDIA_FORMAT_MAP
from synapse.http.server import (
    DirectServeJsonResource,
    respond_with_json,
    set_corp_headers,
    set_cors_headers,
)
from synapse.http.servlet import parse_integer, parse_string
from synapse.http.site import SynapseRequest
from synapse.rest.media.v1.media_storage import MediaStorage

from ._base import (
    FileInfo,
    ThumbnailInfo,
    parse_media_id,
    respond_404,
    respond_with_file,
    respond_with_responder,
)

if TYPE_CHECKING:
    from synapse.rest.media.v1.media_repository import MediaRepository
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ThumbnailResource(DirectServeJsonResource):
    isLeaf = True

    def __init__(
        self,
        hs: "HomeServer",
        media_repo: "MediaRepository",
        media_storage: MediaStorage,
    ):
        super().__init__()

        self.store = hs.get_datastores().main
        self.media_repo = media_repo
        self.media_storage = media_storage
        self.dynamic_thumbnails = hs.config.media.dynamic_thumbnails
        self.server_name = hs.hostname

    async def _async_render_GET(self, request: SynapseRequest) -> None:
        set_cors_headers(request)
        set_corp_headers(request)
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
        self,
        request: SynapseRequest,
        media_id: str,
        width: int,
        height: int,
        method: str,
        m_type: str,
    ) -> None:
        media_info = await self.store.get_local_media(media_id)

        if not media_info:
            respond_404(request)
            return
        if media_info["quarantined_by"]:
            logger.info("Media is quarantined")
            respond_404(request)
            return

        thumbnail_infos = await self.store.get_local_media_thumbnails(media_id)
        await self._select_and_respond_with_thumbnail(
            request,
            width,
            height,
            method,
            m_type,
            thumbnail_infos,
            media_id,
            media_id,
            url_cache=bool(media_info["url_cache"]),
            server_name=None,
        )

    async def _select_or_generate_local_thumbnail(
        self,
        request: SynapseRequest,
        media_id: str,
        desired_width: int,
        desired_height: int,
        desired_method: str,
        desired_type: str,
    ) -> None:
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
                    thumbnail=ThumbnailInfo(
                        width=info["thumbnail_width"],
                        height=info["thumbnail_height"],
                        type=info["thumbnail_type"],
                        method=info["thumbnail_method"],
                    ),
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
            url_cache=bool(media_info["url_cache"]),
        )

        if file_path:
            await respond_with_file(request, desired_type, file_path)
        else:
            logger.warning("Failed to generate thumbnail")
            raise SynapseError(400, "Failed to generate thumbnail.")

    async def _select_or_generate_remote_thumbnail(
        self,
        request: SynapseRequest,
        server_name: str,
        media_id: str,
        desired_width: int,
        desired_height: int,
        desired_method: str,
        desired_type: str,
    ) -> None:
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
                    thumbnail=ThumbnailInfo(
                        width=info["thumbnail_width"],
                        height=info["thumbnail_height"],
                        type=info["thumbnail_type"],
                        method=info["thumbnail_method"],
                    ),
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
        self,
        request: SynapseRequest,
        server_name: str,
        media_id: str,
        width: int,
        height: int,
        method: str,
        m_type: str,
    ) -> None:
        # TODO: Don't download the whole remote file
        # We should proxy the thumbnail from the remote server instead of
        # downloading the remote file and generating our own thumbnails.
        media_info = await self.media_repo.get_remote_media_info(server_name, media_id)

        thumbnail_infos = await self.store.get_remote_media_thumbnails(
            server_name, media_id
        )
        await self._select_and_respond_with_thumbnail(
            request,
            width,
            height,
            method,
            m_type,
            thumbnail_infos,
            media_id,
            media_info["filesystem_id"],
            url_cache=False,
            server_name=server_name,
        )

    async def _select_and_respond_with_thumbnail(
        self,
        request: SynapseRequest,
        desired_width: int,
        desired_height: int,
        desired_method: str,
        desired_type: str,
        thumbnail_infos: List[Dict[str, Any]],
        media_id: str,
        file_id: str,
        url_cache: bool,
        server_name: Optional[str] = None,
    ) -> None:
        """
        Respond to a request with an appropriate thumbnail from the previously generated thumbnails.

        Args:
            request: The incoming request.
            desired_width: The desired width, the returned thumbnail may be larger than this.
            desired_height: The desired height, the returned thumbnail may be larger than this.
            desired_method: The desired method used to generate the thumbnail.
            desired_type: The desired content-type of the thumbnail.
            thumbnail_infos: A list of dictionaries of candidate thumbnails.
            file_id: The ID of the media that a thumbnail is being requested for.
            url_cache: True if this is from a URL cache.
            server_name: The server name, if this is a remote thumbnail.
        """
        logger.debug(
            "_select_and_respond_with_thumbnail: media_id=%s desired=%sx%s (%s) thumbnail_infos=%s",
            media_id,
            desired_width,
            desired_height,
            desired_method,
            thumbnail_infos,
        )

        # If `dynamic_thumbnails` is enabled, we expect Synapse to go down a
        # different code path to handle it.
        assert not self.dynamic_thumbnails

        if thumbnail_infos:
            file_info = self._select_thumbnail(
                desired_width,
                desired_height,
                desired_method,
                desired_type,
                thumbnail_infos,
                file_id,
                url_cache,
                server_name,
            )
            if not file_info:
                logger.info("Couldn't find a thumbnail matching the desired inputs")
                respond_404(request)
                return

            # The thumbnail property must exist.
            assert file_info.thumbnail is not None

            responder = await self.media_storage.fetch_media(file_info)
            if responder:
                await respond_with_responder(
                    request,
                    responder,
                    file_info.thumbnail.type,
                    file_info.thumbnail.length,
                )
                return

            # If we can't find the thumbnail we regenerate it. This can happen
            # if e.g. we've deleted the thumbnails but still have the original
            # image somewhere.
            #
            # Since we have an entry for the thumbnail in the DB we a) know we
            # have have successfully generated the thumbnail in the past (so we
            # don't need to worry about repeatedly failing to generate
            # thumbnails), and b) have already calculated that appropriate
            # width/height/method so we can just call the "generate exact"
            # methods.

            # First let's check that we do actually have the original image
            # still. This will throw a 404 if we don't.
            # TODO: We should refetch the thumbnails for remote media.
            await self.media_storage.ensure_media_is_in_local_cache(
                FileInfo(server_name, file_id, url_cache=url_cache)
            )

            if server_name:
                await self.media_repo.generate_remote_exact_thumbnail(
                    server_name,
                    file_id=file_id,
                    media_id=media_id,
                    t_width=file_info.thumbnail.width,
                    t_height=file_info.thumbnail.height,
                    t_method=file_info.thumbnail.method,
                    t_type=file_info.thumbnail.type,
                )
            else:
                await self.media_repo.generate_local_exact_thumbnail(
                    media_id=media_id,
                    t_width=file_info.thumbnail.width,
                    t_height=file_info.thumbnail.height,
                    t_method=file_info.thumbnail.method,
                    t_type=file_info.thumbnail.type,
                    url_cache=url_cache,
                )

            responder = await self.media_storage.fetch_media(file_info)
            await respond_with_responder(
                request,
                responder,
                file_info.thumbnail.type,
                file_info.thumbnail.length,
            )
        else:
            # This might be because:
            # 1. We can't create thumbnails for the given media (corrupted or
            #    unsupported file type), or
            # 2. The thumbnailing process never ran or errored out initially
            #    when the media was first uploaded (these bugs should be
            #    reported and fixed).
            # Note that we don't attempt to generate a thumbnail now because
            # `dynamic_thumbnails` is disabled.
            logger.info("Failed to find any generated thumbnails")

            respond_with_json(
                request,
                400,
                cs_error(
                    "Cannot find any thumbnails for the requested media (%r). This might mean the media is not a supported_media_format=(%s) or that thumbnailing failed for some other reason. (Dynamic thumbnails are disabled on this server.)"
                    % (
                        request.postpath,
                        ", ".join(THUMBNAIL_SUPPORTED_MEDIA_FORMAT_MAP.keys()),
                    ),
                    code=Codes.UNKNOWN,
                ),
                send_cors=True,
            )

    def _select_thumbnail(
        self,
        desired_width: int,
        desired_height: int,
        desired_method: str,
        desired_type: str,
        thumbnail_infos: List[Dict[str, Any]],
        file_id: str,
        url_cache: bool,
        server_name: Optional[str],
    ) -> Optional[FileInfo]:
        """
        Choose an appropriate thumbnail from the previously generated thumbnails.

        Args:
            desired_width: The desired width, the returned thumbnail may be larger than this.
            desired_height: The desired height, the returned thumbnail may be larger than this.
            desired_method: The desired method used to generate the thumbnail.
            desired_type: The desired content-type of the thumbnail.
            thumbnail_infos: A list of dictionaries of candidate thumbnails.
            file_id: The ID of the media that a thumbnail is being requested for.
            url_cache: True if this is from a URL cache.
            server_name: The server name, if this is a remote thumbnail.

        Returns:
             The thumbnail which best matches the desired parameters.
        """
        desired_method = desired_method.lower()

        # The chosen thumbnail.
        thumbnail_info = None

        d_w = desired_width
        d_h = desired_height

        if desired_method == "crop":
            # Thumbnails that match equal or larger sizes of desired width/height.
            crop_info_list: List[Tuple[int, int, int, bool, int, Dict[str, Any]]] = []
            # Other thumbnails.
            crop_info_list2: List[Tuple[int, int, int, bool, int, Dict[str, Any]]] = []
            for info in thumbnail_infos:
                # Skip thumbnails generated with different methods.
                if info["thumbnail_method"] != "crop":
                    continue

                t_w = info["thumbnail_width"]
                t_h = info["thumbnail_height"]
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
            # Pick the most appropriate thumbnail. Some values of `desired_width` and
            # `desired_height` may result in a tie, in which case we avoid comparing on
            # the thumbnail info dictionary and pick the thumbnail that appears earlier
            # in the list of candidates.
            if crop_info_list:
                thumbnail_info = min(crop_info_list, key=lambda t: t[:-1])[-1]
            elif crop_info_list2:
                thumbnail_info = min(crop_info_list2, key=lambda t: t[:-1])[-1]
        elif desired_method == "scale":
            # Thumbnails that match equal or larger sizes of desired width/height.
            info_list: List[Tuple[int, bool, int, Dict[str, Any]]] = []
            # Other thumbnails.
            info_list2: List[Tuple[int, bool, int, Dict[str, Any]]] = []

            for info in thumbnail_infos:
                # Skip thumbnails generated with different methods.
                if info["thumbnail_method"] != "scale":
                    continue

                t_w = info["thumbnail_width"]
                t_h = info["thumbnail_height"]
                size_quality = abs((d_w - t_w) * (d_h - t_h))
                type_quality = desired_type != info["thumbnail_type"]
                length_quality = info["thumbnail_length"]
                if t_w >= d_w or t_h >= d_h:
                    info_list.append((size_quality, type_quality, length_quality, info))
                else:
                    info_list2.append(
                        (size_quality, type_quality, length_quality, info)
                    )
            # Pick the most appropriate thumbnail. Some values of `desired_width` and
            # `desired_height` may result in a tie, in which case we avoid comparing on
            # the thumbnail info dictionary and pick the thumbnail that appears earlier
            # in the list of candidates.
            if info_list:
                thumbnail_info = min(info_list, key=lambda t: t[:-1])[-1]
            elif info_list2:
                thumbnail_info = min(info_list2, key=lambda t: t[:-1])[-1]

        if thumbnail_info:
            return FileInfo(
                file_id=file_id,
                url_cache=url_cache,
                server_name=server_name,
                thumbnail=ThumbnailInfo(
                    width=thumbnail_info["thumbnail_width"],
                    height=thumbnail_info["thumbnail_height"],
                    type=thumbnail_info["thumbnail_type"],
                    method=thumbnail_info["thumbnail_method"],
                    length=thumbnail_info["thumbnail_length"],
                ),
            )

        # No matching thumbnail was found.
        return None
