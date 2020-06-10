# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
from typing import Dict, Tuple

from six import iteritems

import twisted.internet.error
import twisted.web.http
from twisted.web.resource import Resource

from synapse.api.errors import (
    FederationDeniedError,
    HttpResponseException,
    NotFoundError,
    RequestSendFailed,
    SynapseError,
)
from synapse.config._base import ConfigError
from synapse.logging.context import defer_to_thread
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.util.async_helpers import Linearizer
from synapse.util.retryutils import NotRetryingDestination
from synapse.util.stringutils import random_string

from ._base import (
    FileInfo,
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
from .thumbnailer import Thumbnailer
from .upload_resource import UploadResource

logger = logging.getLogger(__name__)


UPDATE_RECENTLY_ACCESSED_TS = 60 * 1000


class MediaRepository(object):
    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.client = hs.get_http_client()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.max_upload_size = hs.config.max_upload_size
        self.max_image_pixels = hs.config.max_image_pixels

        self.primary_base_path = hs.config.media_store_path
        self.filepaths = MediaFilePaths(self.primary_base_path)

        self.dynamic_thumbnails = hs.config.dynamic_thumbnails
        self.thumbnail_requirements = hs.config.thumbnail_requirements

        self.remote_media_linearizer = Linearizer(name="media_remote")

        self.recently_accessed_remotes = set()
        self.recently_accessed_locals = set()

        self.federation_domain_whitelist = hs.config.federation_domain_whitelist

        # List of StorageProviders where we should search for media and
        # potentially upload to.
        storage_providers = []

        for clz, provider_config, wrapper_config in hs.config.media_storage_providers:
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

    def _start_update_recently_accessed(self):
        return run_as_background_process(
            "update_recently_accessed_media", self._update_recently_accessed
        )

    async def _update_recently_accessed(self):
        remote_media = self.recently_accessed_remotes
        self.recently_accessed_remotes = set()

        local_media = self.recently_accessed_locals
        self.recently_accessed_locals = set()

        await self.store.update_cached_last_access_time(
            local_media, remote_media, self.clock.time_msec()
        )

    def mark_recently_accessed(self, server_name, media_id):
        """Mark the given media as recently accessed.

        Args:
            server_name (str|None): Origin server of media, or None if local
            media_id (str): The media ID of the content
        """
        if server_name:
            self.recently_accessed_remotes.add((server_name, media_id))
        else:
            self.recently_accessed_locals.add(media_id)

    async def create_content(
        self, media_type, upload_name, content, content_length, auth_user
    ):
        """Store uploaded content for a local user and return the mxc URL

        Args:
            media_type(str): The content type of the file
            upload_name(str): The name of the file
            content: A file like object that is the content to store
            content_length(int): The length of the content
            auth_user(str): The user_id of the uploader

        Returns:
            Deferred[str]: The mxc url of the stored content
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

        return "mxc://%s/%s" % (self.server_name, media_id)

    async def get_local_media(self, request, media_id, name):
        """Responds to reqests for local media, if exists, or returns 404.

        Args:
            request(twisted.web.http.Request)
            media_id (str): The media ID of the content. (This is the same as
                the file_id for local content.)
            name (str|None): Optional name that, if specified, will be used as
                the filename in the Content-Disposition header of the response.

        Returns:
            Deferred: Resolves once a response has successfully been written
                to request
        """
        media_info = await self.store.get_local_media(media_id)
        if not media_info or media_info["quarantined_by"]:
            respond_404(request)
            return

        self.mark_recently_accessed(None, media_id)

        media_type = media_info["media_type"]
        media_length = media_info["media_length"]
        upload_name = name if name else media_info["upload_name"]
        url_cache = media_info["url_cache"]

        file_info = FileInfo(None, media_id, url_cache=url_cache)

        responder = await self.media_storage.fetch_media(file_info)
        await respond_with_responder(
            request, responder, media_type, media_length, upload_name
        )

    async def get_remote_media(self, request, server_name, media_id, name):
        """Respond to requests for remote media.

        Args:
            request(twisted.web.http.Request)
            server_name (str): Remote server_name where the media originated.
            media_id (str): The media ID of the content (as defined by the
                remote server).
            name (str|None): Optional name that, if specified, will be used as
                the filename in the Content-Disposition header of the response.

        Returns:
            Deferred: Resolves once a response has successfully been written
                to request
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
        with (await self.remote_media_linearizer.queue(key)):
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

    async def get_remote_media_info(self, server_name, media_id):
        """Gets the media info associated with the remote file, downloading
        if necessary.

        Args:
            server_name (str): Remote server_name where the media originated.
            media_id (str): The media ID of the content (as defined by the
                remote server).

        Returns:
            Deferred[dict]: The media_info of the file
        """
        if (
            self.federation_domain_whitelist is not None
            and server_name not in self.federation_domain_whitelist
        ):
            raise FederationDeniedError(server_name)

        # We linearize here to ensure that we don't try and download remote
        # media multiple times concurrently
        key = (server_name, media_id)
        with (await self.remote_media_linearizer.queue(key)):
            responder, media_info = await self._get_remote_media_impl(
                server_name, media_id
            )

        # Ensure we actually use the responder so that it releases resources
        if responder:
            with responder:
                pass

        return media_info

    async def _get_remote_media_impl(self, server_name, media_id):
        """Looks for media in local cache, if not there then attempt to
        download from remote server.

        Args:
            server_name (str): Remote server_name where the media originated.
            media_id (str): The media ID of the content (as defined by the
                remote server).

        Returns:
            Deferred[(Responder, media_info)]
        """
        media_info = await self.store.get_cached_remote_media(server_name, media_id)

        # file_id is the ID we use to track the file locally. If we've already
        # seen the file then reuse the existing ID, otherwise genereate a new
        # one.
        if media_info:
            file_id = media_info["filesystem_id"]
        else:
            file_id = random_string(24)

        file_info = FileInfo(server_name, file_id)

        # If we have an entry in the DB, try and look for it
        if media_info:
            if media_info["quarantined_by"]:
                logger.info("Media is quarantined")
                raise NotFoundError()

            responder = await self.media_storage.fetch_media(file_info)
            if responder:
                return responder, media_info

        # Failed to find the file anywhere, lets download it.

        media_info = await self._download_remote_file(server_name, media_id, file_id)

        responder = await self.media_storage.fetch_media(file_info)
        return responder, media_info

    async def _download_remote_file(self, server_name, media_id, file_id):
        """Attempt to download the remote file from the given server name,
        using the given file_id as the local id.

        Args:
            server_name (str): Originating server
            media_id (str): The media ID of the content (as defined by the
                remote server). This is different than the file_id, which is
                locally generated.
            file_id (str): Local file ID

        Returns:
            Deferred[MediaInfo]
        """

        file_info = FileInfo(server_name=server_name, file_id=file_id)

        with self.media_storage.store_into_file(file_info) as (f, fname, finish):
            request_path = "/".join(
                ("/_matrix/media/v1/download", server_name, media_id)
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

        media_type = headers[b"Content-Type"][0].decode("ascii")
        upload_name = get_filename_from_headers(headers)
        time_now_ms = self.clock.time_msec()

        logger.info("Stored remote media in file %r", fname)

        await self.store.store_cached_remote_media(
            origin=server_name,
            media_id=media_id,
            media_type=media_type,
            time_now_ms=self.clock.time_msec(),
            upload_name=upload_name,
            media_length=length,
            filesystem_id=file_id,
        )

        media_info = {
            "media_type": media_type,
            "media_length": length,
            "upload_name": upload_name,
            "created_ts": time_now_ms,
            "filesystem_id": file_id,
        }

        await self._generate_thumbnails(server_name, media_id, file_id, media_type)

        return media_info

    def _get_thumbnail_requirements(self, media_type):
        return self.thumbnail_requirements.get(media_type, ())

    def _generate_thumbnail(self, thumbnailer, t_width, t_height, t_method, t_type):
        m_width = thumbnailer.width
        m_height = thumbnailer.height

        if m_width * m_height >= self.max_image_pixels:
            logger.info(
                "Image too large to thumbnail %r x %r > %r",
                m_width,
                m_height,
                self.max_image_pixels,
            )
            return

        if thumbnailer.transpose_method is not None:
            m_width, m_height = thumbnailer.transpose()

        if t_method == "crop":
            t_byte_source = thumbnailer.crop(t_width, t_height, t_type)
        elif t_method == "scale":
            t_width, t_height = thumbnailer.aspect(t_width, t_height)
            t_width = min(m_width, t_width)
            t_height = min(m_height, t_height)
            t_byte_source = thumbnailer.scale(t_width, t_height, t_type)
        else:
            t_byte_source = None

        return t_byte_source

    async def generate_local_exact_thumbnail(
        self, media_id, t_width, t_height, t_method, t_type, url_cache
    ):
        input_path = await self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(None, media_id, url_cache=url_cache)
        )

        thumbnailer = Thumbnailer(input_path)
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
                    thumbnail=True,
                    thumbnail_width=t_width,
                    thumbnail_height=t_height,
                    thumbnail_method=t_method,
                    thumbnail_type=t_type,
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

    async def generate_remote_exact_thumbnail(
        self, server_name, file_id, media_id, t_width, t_height, t_method, t_type
    ):
        input_path = await self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(server_name, file_id, url_cache=False)
        )

        thumbnailer = Thumbnailer(input_path)
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
                    thumbnail=True,
                    thumbnail_width=t_width,
                    thumbnail_height=t_height,
                    thumbnail_method=t_method,
                    thumbnail_type=t_type,
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

    async def _generate_thumbnails(
        self, server_name, media_id, file_id, media_type, url_cache=False
    ):
        """Generate and store thumbnails for an image.

        Args:
            server_name (str|None): The server name if remote media, else None if local
            media_id (str): The media ID of the content. (This is the same as
                the file_id for local content)
            file_id (str): Local file ID
            media_type (str): The content type of the file
            url_cache (bool): If we are thumbnailing images downloaded for the URL cache,
                used exclusively by the url previewer

        Returns:
            Deferred[dict]: Dict with "width" and "height" keys of original image
        """
        requirements = self._get_thumbnail_requirements(media_type)
        if not requirements:
            return

        input_path = await self.media_storage.ensure_media_is_in_local_cache(
            FileInfo(server_name, file_id, url_cache=url_cache)
        )

        thumbnailer = Thumbnailer(input_path)
        m_width = thumbnailer.width
        m_height = thumbnailer.height

        if m_width * m_height >= self.max_image_pixels:
            logger.info(
                "Image too large to thumbnail %r x %r > %r",
                m_width,
                m_height,
                self.max_image_pixels,
            )
            return

        if thumbnailer.transpose_method is not None:
            m_width, m_height = await defer_to_thread(
                self.hs.get_reactor(), thumbnailer.transpose
            )

        # We deduplicate the thumbnail sizes by ignoring the cropped versions if
        # they have the same dimensions of a scaled one.
        thumbnails = {}  # type: Dict[Tuple[int, int, str], str]
        for r_width, r_height, r_method, r_type in requirements:
            if r_method == "crop":
                thumbnails.setdefault((r_width, r_height, r_type), r_method)
            elif r_method == "scale":
                t_width, t_height = thumbnailer.aspect(r_width, r_height)
                t_width = min(m_width, t_width)
                t_height = min(m_height, t_height)
                thumbnails[(t_width, t_height, r_type)] = r_method

        # Now we generate the thumbnails for each dimension, store it
        for (t_width, t_height, t_type), t_method in iteritems(thumbnails):
            # Generate the thumbnail
            if t_method == "crop":
                t_byte_source = await defer_to_thread(
                    self.hs.get_reactor(), thumbnailer.crop, t_width, t_height, t_type
                )
            elif t_method == "scale":
                t_byte_source = await defer_to_thread(
                    self.hs.get_reactor(), thumbnailer.scale, t_width, t_height, t_type
                )
            else:
                logger.error("Unrecognized method: %r", t_method)
                continue

            if not t_byte_source:
                continue

            try:
                file_info = FileInfo(
                    server_name=server_name,
                    file_id=file_id,
                    thumbnail=True,
                    thumbnail_width=t_width,
                    thumbnail_height=t_height,
                    thumbnail_method=t_method,
                    thumbnail_type=t_type,
                    url_cache=url_cache,
                )

                output_path = await self.media_storage.store_file(
                    t_byte_source, file_info
                )
            finally:
                t_byte_source.close()

            t_len = os.path.getsize(output_path)

            # Write to database
            if server_name:
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
            else:
                await self.store.store_local_thumbnail(
                    media_id, t_width, t_height, t_type, t_method, t_len
                )

        return {"width": m_width, "height": m_height}

    async def delete_old_remote_media(self, before_ts):
        old_media = await self.store.get_remote_media_before(before_ts)

        deleted = 0

        for media in old_media:
            origin = media["media_origin"]
            media_id = media["media_id"]
            file_id = media["filesystem_id"]
            key = (origin, media_id)

            logger.info("Deleting: %r", key)

            # TODO: Should we delete from the backup store

            with (await self.remote_media_linearizer.queue(key)):
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


class MediaRepositoryResource(Resource):
    """File uploading and downloading.

    Uploads are POSTed to a resource which returns a token which is used to GET
    the download::

        => POST /_matrix/media/v1/upload HTTP/1.1
           Content-Type: <media-type>
           Content-Length: <content-length>

           <media>

        <= HTTP/1.1 200 OK
           Content-Type: application/json

           { "content_uri": "mxc://<server-name>/<media-id>" }

        => GET /_matrix/media/v1/download/<server-name>/<media-id> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: <media-type>
           Content-Disposition: attachment;filename=<upload-filename>

           <media>

    Clients can get thumbnails by supplying a desired width and height and
    thumbnailing method::

        => GET /_matrix/media/v1/thumbnail/<server_name>
                /<media-id>?width=<w>&height=<h>&method=<m> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: image/jpeg or image/png

           <thumbnail>

    The thumbnail methods are "crop" and "scale". "scale" trys to return an
    image where either the width or the height is smaller than the requested
    size. The client should then scale and letterbox the image if it needs to
    fit within a given rectangle. "crop" trys to return an image where the
    width and height are close to the requested size and the aspect matches
    the requested size. The client should scale the image if it needs to fit
    within a given rectangle.
    """

    def __init__(self, hs):
        # If we're not configured to use it, raise if we somehow got here.
        if not hs.config.can_load_media_repo:
            raise ConfigError("Synapse is not configured to use a media repo.")

        super().__init__()
        media_repo = hs.get_media_repository()

        self.putChild(b"upload", UploadResource(hs, media_repo))
        self.putChild(b"download", DownloadResource(hs, media_repo))
        self.putChild(
            b"thumbnail", ThumbnailResource(hs, media_repo, media_repo.media_storage)
        )
        if hs.config.url_preview_enabled:
            self.putChild(
                b"preview_url",
                PreviewUrlResource(hs, media_repo, media_repo.media_storage),
            )
        self.putChild(b"config", MediaConfigResource(hs))
