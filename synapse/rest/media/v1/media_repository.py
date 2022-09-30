# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
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
import errno
import logging
import os
import shutil
from io import BytesIO
from typing import IO, TYPE_CHECKING, Dict, List, Optional, Set, Tuple

from matrix_common.types.mxc_uri import MXCUri

import twisted.internet.error
import twisted.web.http
from twisted.internet.defer import Deferred
from twisted.web.resource import Resource

from synapse.api.errors import (
    FederationDeniedError,
    HttpResponseException,
    NotFoundError,
    RequestSendFailed,
    SynapseError,
)
from synapse.config._base import ConfigError
from synapse.config.repository import ThumbnailRequirement
from synapse.http.site import SynapseRequest
from synapse.logging.context import defer_to_thread
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import UserID
from synapse.util.async_helpers import Linearizer
from synapse.util.retryutils import NotRetryingDestination
from synapse.util.stringutils import random_string

from ._base import (
    FileInfo,
    Responder,
    ThumbnailInfo,
    get_filename_from_headers,
    respond_404,
    respond_with_responder,
)
from .config_resource import MediaConfigResource
from .download_resource import DownloadResource
from .filepath import MediaFilePaths
from .media_storage import MediaStorage
from .preview_url_resource import PreviewUrlResource
from .storage_provider import StorageProviderWrapper
from .thumbnail_resource import ThumbnailResource
from .thumbnailer import Thumbnailer, ThumbnailError
from .upload_resource import UploadResource

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# How often to run the background job to update the "recently accessed"
# attribute of local and remote media.
UPDATE_RECENTLY_ACCESSED_TS = 60 * 1000  # 1 minute
# How often to run the background job to check for local and remote media
# that should be purged according to the configured media retention settings.
MEDIA_RETENTION_CHECK_PERIOD_MS = 60 * 60 * 1000  # 1 hour


class MediaRepository:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.client = hs.get_federation_http_client()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.store = hs.get_datastores().main
        self.max_upload_size = hs.config.media.max_upload_size
        self.max_image_pixels = hs.config.media.max_image_pixels

        Thumbnailer.set_limits(self.max_image_pixels)

        self.primary_base_path: str = hs.config.media.media_store_path
        self.filepaths: MediaFilePaths = MediaFilePaths(self.primary_base_path)

        self.dynamic_thumbnails = hs.config.media.dynamic_thumbnails
        self.thumbnail_requirements = hs.config.media.thumbnail_requirements

        self.remote_media_linearizer = Linearizer(name="media_remote")

        self.recently_accessed_remotes: Set[Tuple[str, str]] = set()
        self.recently_accessed_locals: Set[str] = set()

        self.federation_domain_whitelist = (
            hs.config.federation.federation_domain_whitelist
        )

        # List of StorageProviders where we should search for media and
        # potentially upload to.
        storage_providers = []

        for (
            clz,
            provider_config,
            wrapper_config,
        ) in hs.config.media.media_storage_providers:
            backend = clz(hs, provider_config)
            provider = StorageProviderWrapper(
                backend,
                store_local=wrapper_config.store_local,
                store_remote=wrapper_config.store_remote,
                store_synchronous=wrapper_config.store_synchronous,
            )
            storage_providers.append(provider)

        self.media_storage = MediaStorage(
            self.hs, self.primary_base_path, self.filepaths, storage_providers
        )

        self.clock.looping_call(
            self._start_update_recently_accessed, UPDATE_RECENTLY_ACCESSED_TS
        )

        # Media retention configuration options
        self._media_retention_local_media_lifetime_ms = (
            hs.config.media.media_retention_local_media_lifetime_ms
        )
        self._media_retention_remote_media_lifetime_ms = (
            hs.config.media.media_retention_remote_media_lifetime_ms
        )

        # Check whether local or remote media retention is configured
        if (
            hs.config.media.media_retention_local_media_lifetime_ms is not None
            or hs.config.media.media_retention_remote_media_lifetime_ms is not None
        ):
            # Run the background job to apply media retention rules routinely,
            # with the duration between runs dictated by the homeserver config.
            self.clock.looping_call(
                self._start_apply_media_retention_rules,
                MEDIA_RETENTION_CHECK_PERIOD_MS,
            )

    def _start_update_recently_accessed(self) -> Deferred:
        return run_as_background_process(
            "update_recently_accessed_media", self._update_recently_accessed
        )

    def _start_apply_media_retention_rules(self) -> Deferred:
        return run_as_background_process(
            "apply_media_retention_rules", self._apply_media_retention_rules
        )

    async def _update_recently_accessed(self) -> None:
        remote_media = self.recently_accessed_remotes
        self.recently_accessed_remotes = set()

        local_media = self.recently_accessed_locals
        self.recently_accessed_locals = set()

        await self.store.update_cached_last_access_time(
            local_media, remote_media, self.clock.time_msec()
        )

    def mark_recently_accessed(self, server_name: Optional[str], media_id: str) -> None:
        """Mark the given media as recently accessed.

        Args:
            server_name: Origin server of media, or None if local
            media_id: The media ID of the content
        """
        if server_name:
            self.recently_accessed_remotes.add((server_name, media_id))
        else:
            self.recently_accessed_locals.add(media_id)

    async def create_content(
        self,
        media_type: str,
        upload_name: Optional[str],
        content: IO,
        content_length: int,
        auth_user: UserID,
    ) -> MXCUri:
        """Store uploaded content for a local user and return the mxc URL

        Args:
            media_type: The content type of the file.
            upload_name: The name of the file, if provided.
            content: A file like object that is the content to store
            content_length: The length of the content
            auth_user: The user_id of the uploader

        Returns:
            The mxc url of the stored content
        """

        media_id = random_string(24)

        file_info = FileInfo(server_name=None, file_id=media_id)

        fname = await self.media_storage.store_file(content, file_info)

        logger.info("Stored local media in file %r", fname)

        await self.store.store_local_media(
            media_id=media_id,
            media_type=media_type,
            time_now_ms=self.clock.time_msec(),
            upload_name=upload_name,
            media_length=content_length,
            user_id=auth_user,
        )

        await self._generate_thumbnails(None, media_id, media_id, media_type)

        return MXCUri(self.server_name, media_id)

    async def get_local_media(
        self, request: SynapseRequest, media_id: str, name: Optional[str]
    ) -> None:
        """Responds to requests for local media, if exists, or returns 404.

        Args:
            request: The incoming request.
            media_id: The media ID of the content. (This is the same as
                the file_id for local content.)
            name: Optional name that, if specified, will be used as
                the filename in the Content-Disposition header of the response.

        Returns:
            Resolves once a response has successfully been written to request
        """
        media_info = await self.store.get_local_media(media_id)
        if not media_info or media_info["quarantined_by"]:
            respond_404(request)
            return

        self.mark_recently_accessed(None, media_id)

        media_type = media_info["media_type"]
        if not media_type:
            media_type = "application/octet-stream"
        media_length = media_info["media_length"]
        upload_name = name if name else media_info["upload_name"]
        url_cache = media_info["url_cache"]

        file_info = FileInfo(None, media_id, url_cache=bool(url_cache))

        responder = await self.media_storage.fetch_media(file_info)
        await respond_with_responder(
            request, responder, media_type, media_length, upload_name
        )

    async def get_remote_media(
        self,
        request: SynapseRequest,
        server_name: str,
        media_id: str,
        name: Optional[str],
    ) -> None:
        """Respond to requests for remote media.

        Args:
            request: The incoming request.
            server_name: Remote server_name where the media originated.
            media_id: The media ID of the content (as defined by the remote server).
            name: Optional name that, if specified, will be used as
                the filename in the Content-Disposition header of the response.

        Returns:
            Resolves once a response has successfully been written to request
        """
        if (
            self.federation_domain_whitelist is not None
            and server_name not in self.federation_domain_whitelist
        ):
            raise FederationDeniedError(server_name)

        self.mark_recently_accessed(server_name, media_id)

        # We linearize here to ensure that we don't try and download remote
        # media multiple times concurrently
        key = (server_name, media_id)
        async with self.remote_media_linearizer.queue(key):
            responder, media_info = await self._get_remote_media_impl(
                server_name, media_id
            )

        # We deliberately stream the file outside the lock
        if responder:
            media_type = media_info["media_type"]
            media_length = media_info["media_length"]
            upload_name = name if name else media_info["upload_name"]
            await respond_with_responder(
                request, responder, media_type, media_length, upload_name
            )
        else:
            respond_404(request)

    async def get_remote_media_info(self, server_name: str, media_id: str) -> dict:
        """Gets the media info associated with the remote file, downloading
        if necessary.

        Args:
            server_name: Remote server_name where the media originated.
            media_id: The media ID of the content (as defined by the remote server).

        Returns:
            The media info of the file
        """
        if (
            self.federation_domain_whitelist is not None
            and server_name not in self.federation_domain_whitelist
        ):
            raise FederationDeniedError(server_name)

        # We linearize here to ensure that we don't try and download remote
        # media multiple times concurrently
        key = (server_name, media_id)
        async with self.remote_media_linearizer.queue(key):
            responder, media_info = await self._get_remote_media_impl(
                server_name, media_id
            )

        # Ensure we actually use the responder so that it releases resources
        if responder:
            with responder:
                pass

        return media_info

    async def _get_remote_media_impl(
        self, server_name: str, media_id: str
    ) -> Tuple[Optional[Responder], dict]:
        """Looks for media in local cache, if not there then attempt to
        download from remote server.

        Args:
            server_name (str): Remote server_name where the media originated.
            media_id (str): The media ID of the content (as defined by the
                remote server).

        Returns:
            A tuple of responder and the media info of the file.
        """
        media_info = await self.store.get_cached_remote_media(server_name, media_id)

        # file_id is the ID we use to track the file locally. If we've already
        # seen the file then reuse the existing ID, otherwise generate a new
        # one.

        # If we have an entry in the DB, try and look for it
        if media_info:
            file_id = media_info["filesystem_id"]
            file_info = FileInfo(server_name, file_id)

            if media_info["quarantined_by"]:
                logger.info("Media is quarantined")
                raise NotFoundError()

            if not media_info["media_type"]:
                media_info["media_type"] = "application/octet-stream"

            responder = await self.media_storage.fetch_media(file_info)
            if responder:
                return responder, media_info

        # Failed to find the file anywhere, lets download it.

        try:
            media_info = await self._download_remote_file(
                server_name,
                media_id,
            )
        except SynapseError:
            raise
        except Exception as e:
            # An exception may be because we downloaded media in another
            # process, so let's check if we magically have the media.
            media_info = await self.store.get_cached_remote_media(server_name, media_id)
            if not media_info:
                raise e

        file_id = media_info["filesystem_id"]
        if not media_info["media_type"]:
            media_info["media_type"] = "application/octet-stream"
        file_info = FileInfo(server_name, file_id)

        # We generate thumbnails even if another process downloaded the media
        # as a) it's conceivable that the other download request dies before it
        # generates thumbnails, but mainly b) we want to be sure the thumbnails
        # have finished being generated before responding to the client,
        # otherwise they'll request thumbnails and get a 404 if they're not
        # ready yet.
        await self._generate_thumbnails(
            server_name, media_id, file_id, media_info["media_type"]
        )

        responder = await self.media_storage.fetch_media(file_info)
        return responder, media_info

    async def _download_remote_file(
        self,
        server_name: str,
        media_id: str,
    ) -> dict:
        """Attempt to download the remote file from the given server name,
        using the given file_id as the local id.

        Args:
            server_name: Originating server
            media_id: The media ID of the content (as defined by the
                remote server). This is different than the file_id, which is
                locally generated.
            file_id: Local file ID

        Returns:
            The media info of the file.
        """

        file_id = random_string(24)

        file_info = FileInfo(server_name=server_name, file_id=file_id)

        with self.media_storage.store_into_file(file_info) as (f, fname, finish):
            request_path = "/".join(
                ("/_matrix/media/r0/download", server_name, media_id)
            )
            try:
                length, headers = await self.client.get_file(
                    server_name,
                    request_path,
                    output_stream=f,
                    max_size=self.max_upload_size,
                    args={
                        # tell the remote server to 404 if it doesn't
                        # recognise the server_name, to make sure we don't
                        # end up with a routing loop.
                        "allow_remote": "false"
                    },
                )
            except RequestSendFailed as e:
                logger.warning(
                    "Request failed fetching remote media %s/%s: %r",
                    server_name,
                    media_id,
                    e,
                )
                raise SynapseError(502, "Failed to fetch remote media")

            except HttpResponseException as e:
                logger.warning(
                    "HTTP error fetching remote media %s/%s: %s",
                    server_name,
                    media_id,
                    e.response,
                )
                if e.code == twisted.web.http.NOT_FOUND:
                    raise e.to_synapse_error()
                raise SynapseError(502, "Failed to fetch remote media")

            except SynapseError:
                logger.warning(
                    "Failed to fetch remote media %s/%s", server_name, media_id
                )
                raise
            except NotRetryingDestination:
                logger.warning("Not retrying destination %r", server_name)
                raise SynapseError(502, "Failed to fetch remote media")
            except Exception:
                logger.exception(
                    "Failed to fetch remote media %s/%s", server_name, media_id
                )
                raise SynapseError(502, "Failed to fetch remote media")

            await finish()

            if b"Content-Type" in headers:
                media_type = headers[b"Content-Type"][0].decode("ascii")
            else:
                media_type = "application/octet-stream"
            upload_name = get_filename_from_headers(headers)
            time_now_ms = self.clock.time_msec()

            # Multiple remote media download requests can race (when using
            # multiple media repos), so this may throw a violation constraint
            # exception. If it does we'll delete the newly downloaded file from
            # disk (as we're in the ctx manager).
            #
            # However: we've already called `finish()` so we may have also
            # written to the storage providers. This is preferable to the
            # alternative where we call `finish()` *after* this, where we could
            # end up having an entry in the DB but fail to write the files to
            # the storage providers.
            await self.store.store_cached_remote_media(
                origin=server_name,
                media_id=media_id,
                media_type=media_type,
                time_now_ms=self.clock.time_msec(),
                upload_name=upload_name,
                media_length=length,
                filesystem_id=file_id,
            )

        logger.info("Stored remote media in file %r", fname)

        media_info = {
            "media_type": media_type,
            "media_length": length,
            "upload_name": upload_name,
            "created_ts": time_now_ms,
            "filesystem_id": file_id,
        }

        return media_info

    def _get_thumbnail_requirements(
        self, media_type: str
    ) -> Tuple[ThumbnailRequirement, ...]:
        scpos = media_type.find(";")
        if scpos > 0:
            media_type = media_type[:scpos]
        return self.thumbnail_requirements.get(media_type, ())

    def _generate_thumbnail(
        self,
        thumbnailer: Thumbnailer,
        t_width: int,
        t_height: int,
        t_method: str,
        t_type: str,
    ) -> Optional[BytesIO]:
        m_width = thumbnailer.width
        m_height = thumbnailer.height

        if m_width * m_height >= self.max_image_pixels:
            logger.info(
                "Image too large to thumbnail %r x %r > %r",
                m_width,
                m_height,
                self.max_image_pixels,
            )
            return None

        if thumbnailer.transpose_method is not None:
            m_width, m_height = thumbnailer.transpose()

        if t_method == "crop":
            return thumbnailer.crop(t_width, t_height, t_type)
        elif t_method == "scale":
            t_width, t_height = thumbnailer.aspect(t_width, t_height)
            t_width = min(m_width, t_width)
            t_height = min(m_height, t_height)
            return thumbnailer.scale(t_width, t_height, t_type)

        return None

    async def generate_local_exact_thumbnail(
        self,
        media_id: str,
        t_width: int,
        t_height: int,
        t_method: str,
        t_type: str,
        url_cache: bool,
    ) -> Optional[str]:
        input_path = await self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(None, media_id, url_cache=url_cache)
        )

        try:
            thumbnailer = Thumbnailer(input_path)
        except ThumbnailError as e:
            logger.warning(
                "Unable to generate a thumbnail for local media %s using a method of %s and type of %s: %s",
                media_id,
                t_method,
                t_type,
                e,
            )
            return None

        with thumbnailer:
            t_byte_source = await defer_to_thread(
                self.hs.get_reactor(),
                self._generate_thumbnail,
                thumbnailer,
                t_width,
                t_height,
                t_method,
                t_type,
            )

        if t_byte_source:
            try:
                file_info = FileInfo(
                    server_name=None,
                    file_id=media_id,
                    url_cache=url_cache,
                    thumbnail=ThumbnailInfo(
                        width=t_width,
                        height=t_height,
                        method=t_method,
                        type=t_type,
                    ),
                )

                output_path = await self.media_storage.store_file(
                    t_byte_source, file_info
                )
            finally:
                t_byte_source.close()

            logger.info("Stored thumbnail in file %r", output_path)

            t_len = os.path.getsize(output_path)

            await self.store.store_local_thumbnail(
                media_id, t_width, t_height, t_type, t_method, t_len
            )

            return output_path

        # Could not generate thumbnail.
        return None

    async def generate_remote_exact_thumbnail(
        self,
        server_name: str,
        file_id: str,
        media_id: str,
        t_width: int,
        t_height: int,
        t_method: str,
        t_type: str,
    ) -> Optional[str]:
        input_path = await self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(server_name, file_id)
        )

        try:
            thumbnailer = Thumbnailer(input_path)
        except ThumbnailError as e:
            logger.warning(
                "Unable to generate a thumbnail for remote media %s from %s using a method of %s and type of %s: %s",
                media_id,
                server_name,
                t_method,
                t_type,
                e,
            )
            return None

        with thumbnailer:
            t_byte_source = await defer_to_thread(
                self.hs.get_reactor(),
                self._generate_thumbnail,
                thumbnailer,
                t_width,
                t_height,
                t_method,
                t_type,
            )

        if t_byte_source:
            try:
                file_info = FileInfo(
                    server_name=server_name,
                    file_id=file_id,
                    thumbnail=ThumbnailInfo(
                        width=t_width,
                        height=t_height,
                        method=t_method,
                        type=t_type,
                    ),
                )

                output_path = await self.media_storage.store_file(
                    t_byte_source, file_info
                )
            finally:
                t_byte_source.close()

            logger.info("Stored thumbnail in file %r", output_path)

            t_len = os.path.getsize(output_path)

            await self.store.store_remote_media_thumbnail(
                server_name,
                media_id,
                file_id,
                t_width,
                t_height,
                t_type,
                t_method,
                t_len,
            )

            return output_path

        # Could not generate thumbnail.
        return None

    async def _generate_thumbnails(
        self,
        server_name: Optional[str],
        media_id: str,
        file_id: str,
        media_type: str,
        url_cache: bool = False,
    ) -> Optional[dict]:
        """Generate and store thumbnails for an image.

        Args:
            server_name: The server name if remote media, else None if local
            media_id: The media ID of the content. (This is the same as
                the file_id for local content)
            file_id: Local file ID
            media_type: The content type of the file
            url_cache: If we are thumbnailing images downloaded for the URL cache,
                used exclusively by the url previewer

        Returns:
            Dict with "width" and "height" keys of original image or None if the
            media cannot be thumbnailed.
        """
        requirements = self._get_thumbnail_requirements(media_type)
        if not requirements:
            return None

        input_path = await self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(server_name, file_id, url_cache=url_cache)
        )

        try:
            thumbnailer = Thumbnailer(input_path)
        except ThumbnailError as e:
            logger.warning(
                "Unable to generate thumbnails for remote media %s from %s of type %s: %s",
                media_id,
                server_name,
                media_type,
                e,
            )
            return None

        with thumbnailer:
            m_width = thumbnailer.width
            m_height = thumbnailer.height

            if m_width * m_height >= self.max_image_pixels:
                logger.info(
                    "Image too large to thumbnail %r x %r > %r",
                    m_width,
                    m_height,
                    self.max_image_pixels,
                )
                return None

            if thumbnailer.transpose_method is not None:
                m_width, m_height = await defer_to_thread(
                    self.hs.get_reactor(), thumbnailer.transpose
                )

            # We deduplicate the thumbnail sizes by ignoring the cropped versions if
            # they have the same dimensions of a scaled one.
            thumbnails: Dict[Tuple[int, int, str], str] = {}
            for requirement in requirements:
                if requirement.method == "crop":
                    thumbnails.setdefault(
                        (requirement.width, requirement.height, requirement.media_type),
                        requirement.method,
                    )
                elif requirement.method == "scale":
                    t_width, t_height = thumbnailer.aspect(
                        requirement.width, requirement.height
                    )
                    t_width = min(m_width, t_width)
                    t_height = min(m_height, t_height)
                    thumbnails[
                        (t_width, t_height, requirement.media_type)
                    ] = requirement.method

            # Now we generate the thumbnails for each dimension, store it
            for (t_width, t_height, t_type), t_method in thumbnails.items():
                # Generate the thumbnail
                if t_method == "crop":
                    t_byte_source = await defer_to_thread(
                        self.hs.get_reactor(),
                        thumbnailer.crop,
                        t_width,
                        t_height,
                        t_type,
                    )
                elif t_method == "scale":
                    t_byte_source = await defer_to_thread(
                        self.hs.get_reactor(),
                        thumbnailer.scale,
                        t_width,
                        t_height,
                        t_type,
                    )
                else:
                    logger.error("Unrecognized method: %r", t_method)
                    continue

                if not t_byte_source:
                    continue

                file_info = FileInfo(
                    server_name=server_name,
                    file_id=file_id,
                    url_cache=url_cache,
                    thumbnail=ThumbnailInfo(
                        width=t_width,
                        height=t_height,
                        method=t_method,
                        type=t_type,
                    ),
                )

                with self.media_storage.store_into_file(file_info) as (
                    f,
                    fname,
                    finish,
                ):
                    try:
                        await self.media_storage.write_to_file(t_byte_source, f)
                        await finish()
                    finally:
                        t_byte_source.close()

                    t_len = os.path.getsize(fname)

                    # Write to database
                    if server_name:
                        # Multiple remote media download requests can race (when
                        # using multiple media repos), so this may throw a violation
                        # constraint exception. If it does we'll delete the newly
                        # generated thumbnail from disk (as we're in the ctx
                        # manager).
                        #
                        # However: we've already called `finish()` so we may have
                        # also written to the storage providers. This is preferable
                        # to the alternative where we call `finish()` *after* this,
                        # where we could end up having an entry in the DB but fail
                        # to write the files to the storage providers.
                        try:
                            await self.store.store_remote_media_thumbnail(
                                server_name,
                                media_id,
                                file_id,
                                t_width,
                                t_height,
                                t_type,
                                t_method,
                                t_len,
                            )
                        except Exception as e:
                            thumbnail_exists = (
                                await self.store.get_remote_media_thumbnail(
                                    server_name,
                                    media_id,
                                    t_width,
                                    t_height,
                                    t_type,
                                )
                            )
                            if not thumbnail_exists:
                                raise e
                    else:
                        await self.store.store_local_thumbnail(
                            media_id, t_width, t_height, t_type, t_method, t_len
                        )

        return {"width": m_width, "height": m_height}

    async def _apply_media_retention_rules(self) -> None:
        """
        Purge old local and remote media according to the media retention rules
        defined in the homeserver config.
        """
        # Purge remote media
        if self._media_retention_remote_media_lifetime_ms is not None:
            # Calculate a threshold timestamp derived from the configured lifetime. Any
            # media that has not been accessed since this timestamp will be removed.
            remote_media_threshold_timestamp_ms = (
                self.clock.time_msec() - self._media_retention_remote_media_lifetime_ms
            )

            logger.info(
                "Purging remote media last accessed before"
                f" {remote_media_threshold_timestamp_ms}"
            )

            await self.delete_old_remote_media(
                before_ts=remote_media_threshold_timestamp_ms
            )

        # And now do the same for local media
        if self._media_retention_local_media_lifetime_ms is not None:
            # This works the same as the remote media threshold
            local_media_threshold_timestamp_ms = (
                self.clock.time_msec() - self._media_retention_local_media_lifetime_ms
            )

            logger.info(
                "Purging local media last accessed before"
                f" {local_media_threshold_timestamp_ms}"
            )

            await self.delete_old_local_media(
                before_ts=local_media_threshold_timestamp_ms,
                keep_profiles=True,
                delete_quarantined_media=False,
                delete_protected_media=False,
            )

    async def delete_old_remote_media(self, before_ts: int) -> Dict[str, int]:
        old_media = await self.store.get_remote_media_ids(
            before_ts, include_quarantined_media=False
        )

        deleted = 0

        for media in old_media:
            origin = media["media_origin"]
            media_id = media["media_id"]
            file_id = media["filesystem_id"]
            key = (origin, media_id)

            logger.info("Deleting: %r", key)

            # TODO: Should we delete from the backup store

            async with self.remote_media_linearizer.queue(key):
                full_path = self.filepaths.remote_media_filepath(origin, file_id)
                try:
                    os.remove(full_path)
                except OSError as e:
                    logger.warning("Failed to remove file: %r", full_path)
                    if e.errno == errno.ENOENT:
                        pass
                    else:
                        continue

                thumbnail_dir = self.filepaths.remote_media_thumbnail_dir(
                    origin, file_id
                )
                shutil.rmtree(thumbnail_dir, ignore_errors=True)

                await self.store.delete_remote_media(origin, media_id)
                deleted += 1

        return {"deleted": deleted}

    async def delete_local_media_ids(
        self, media_ids: List[str]
    ) -> Tuple[List[str], int]:
        """
        Delete the given local or remote media ID from this server

        Args:
            media_id: The media ID to delete.
        Returns:
            A tuple of (list of deleted media IDs, total deleted media IDs).
        """
        return await self._remove_local_media_from_disk(media_ids)

    async def delete_old_local_media(
        self,
        before_ts: int,
        size_gt: int = 0,
        keep_profiles: bool = True,
        delete_quarantined_media: bool = False,
        delete_protected_media: bool = False,
    ) -> Tuple[List[str], int]:
        """
        Delete local or remote media from this server by size and timestamp. Removes
        media files, any thumbnails and cached URLs.

        Args:
            before_ts: Unix timestamp in ms.
                Files that were last used before this timestamp will be deleted.
            size_gt: Size of the media in bytes. Files that are larger will be deleted.
            keep_profiles: Switch to delete also files that are still used in image data
                (e.g user profile, room avatar). If false these files will be deleted.
            delete_quarantined_media: If True, media marked as quarantined will be deleted.
            delete_protected_media: If True, media marked as protected will be deleted.

        Returns:
            A tuple of (list of deleted media IDs, total deleted media IDs).
        """
        old_media = await self.store.get_local_media_ids(
            before_ts,
            size_gt,
            keep_profiles,
            include_quarantined_media=delete_quarantined_media,
            include_protected_media=delete_protected_media,
        )
        return await self._remove_local_media_from_disk(old_media)

    async def _remove_local_media_from_disk(
        self, media_ids: List[str]
    ) -> Tuple[List[str], int]:
        """
        Delete local or remote media from this server. Removes media files,
        any thumbnails and cached URLs.

        Args:
            media_ids: List of media_id to delete
        Returns:
            A tuple of (list of deleted media IDs, total deleted media IDs).
        """
        removed_media = []
        for media_id in media_ids:
            logger.info("Deleting media with ID '%s'", media_id)
            full_path = self.filepaths.local_media_filepath(media_id)
            try:
                os.remove(full_path)
            except OSError as e:
                logger.warning("Failed to remove file: %r: %s", full_path, e)
                if e.errno == errno.ENOENT:
                    pass
                else:
                    continue

            thumbnail_dir = self.filepaths.local_media_thumbnail_dir(media_id)
            shutil.rmtree(thumbnail_dir, ignore_errors=True)

            await self.store.delete_remote_media(self.server_name, media_id)

            await self.store.delete_url_cache((media_id,))
            await self.store.delete_url_cache_media((media_id,))

            removed_media.append(media_id)

        return removed_media, len(removed_media)


class MediaRepositoryResource(Resource):
    """File uploading and downloading.

    Uploads are POSTed to a resource which returns a token which is used to GET
    the download::

        => POST /_matrix/media/r0/upload HTTP/1.1
           Content-Type: <media-type>
           Content-Length: <content-length>

           <media>

        <= HTTP/1.1 200 OK
           Content-Type: application/json

           { "content_uri": "mxc://<server-name>/<media-id>" }

        => GET /_matrix/media/r0/download/<server-name>/<media-id> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: <media-type>
           Content-Disposition: attachment;filename=<upload-filename>

           <media>

    Clients can get thumbnails by supplying a desired width and height and
    thumbnailing method::

        => GET /_matrix/media/r0/thumbnail/<server_name>
                /<media-id>?width=<w>&height=<h>&method=<m> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: image/jpeg or image/png

           <thumbnail>

    The thumbnail methods are "crop" and "scale". "scale" tries to return an
    image where either the width or the height is smaller than the requested
    size. The client should then scale and letterbox the image if it needs to
    fit within a given rectangle. "crop" tries to return an image where the
    width and height are close to the requested size and the aspect matches
    the requested size. The client should scale the image if it needs to fit
    within a given rectangle.
    """

    def __init__(self, hs: "HomeServer"):
        # If we're not configured to use it, raise if we somehow got here.
        if not hs.config.media.can_load_media_repo:
            raise ConfigError("Synapse is not configured to use a media repo.")

        super().__init__()
        media_repo = hs.get_media_repository()

        self.putChild(b"upload", UploadResource(hs, media_repo))
        self.putChild(b"download", DownloadResource(hs, media_repo))
        self.putChild(
            b"thumbnail", ThumbnailResource(hs, media_repo, media_repo.media_storage)
        )
        if hs.config.media.url_preview_enabled:
            self.putChild(
                b"preview_url",
                PreviewUrlResource(hs, media_repo, media_repo.media_storage),
            )
        self.putChild(b"config", MediaConfigResource(hs))
