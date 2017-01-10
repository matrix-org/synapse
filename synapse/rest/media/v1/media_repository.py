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

from .upload_resource import UploadResource
from .download_resource import DownloadResource
from .thumbnail_resource import ThumbnailResource
from .identicon_resource import IdenticonResource
from .preview_url_resource import PreviewUrlResource
from .filepath import MediaFilePaths

from twisted.web.resource import Resource

from .thumbnailer import Thumbnailer

from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.util.stringutils import random_string
from synapse.api.errors import SynapseError

from twisted.internet import defer, threads

from synapse.util.async import Linearizer
from synapse.util.stringutils import is_ascii
from synapse.util.logcontext import preserve_context_over_fn

import os
import errno
import shutil

import cgi
import logging
import urlparse

logger = logging.getLogger(__name__)


UPDATE_RECENTLY_ACCESSED_REMOTES_TS = 60 * 1000


class MediaRepository(object):
    def __init__(self, hs):
        self.auth = hs.get_auth()
        self.client = MatrixFederationHttpClient(hs)
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.max_upload_size = hs.config.max_upload_size
        self.max_image_pixels = hs.config.max_image_pixels
        self.filepaths = MediaFilePaths(hs.config.media_store_path)
        self.dynamic_thumbnails = hs.config.dynamic_thumbnails
        self.thumbnail_requirements = hs.config.thumbnail_requirements

        self.remote_media_linearizer = Linearizer(name="media_remote")

        self.recently_accessed_remotes = set()

        self.clock.looping_call(
            self._update_recently_accessed_remotes,
            UPDATE_RECENTLY_ACCESSED_REMOTES_TS
        )

    @defer.inlineCallbacks
    def _update_recently_accessed_remotes(self):
        media = self.recently_accessed_remotes
        self.recently_accessed_remotes = set()

        yield self.store.update_cached_last_access_time(
            media, self.clock.time_msec()
        )

    @staticmethod
    def _makedirs(filepath):
        dirname = os.path.dirname(filepath)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

    @defer.inlineCallbacks
    def create_content(self, media_type, upload_name, content, content_length,
                       auth_user):
        media_id = random_string(24)

        fname = self.filepaths.local_media_filepath(media_id)
        self._makedirs(fname)

        # This shouldn't block for very long because the content will have
        # already been uploaded at this point.
        with open(fname, "wb") as f:
            f.write(content)

        logger.info("Stored local media in file %r", fname)

        yield self.store.store_local_media(
            media_id=media_id,
            media_type=media_type,
            time_now_ms=self.clock.time_msec(),
            upload_name=upload_name,
            media_length=content_length,
            user_id=auth_user,
        )
        media_info = {
            "media_type": media_type,
            "media_length": content_length,
        }

        yield self._generate_local_thumbnails(media_id, media_info)

        defer.returnValue("mxc://%s/%s" % (self.server_name, media_id))

    @defer.inlineCallbacks
    def get_remote_media(self, server_name, media_id):
        key = (server_name, media_id)
        with (yield self.remote_media_linearizer.queue(key)):
            media_info = yield self._get_remote_media_impl(server_name, media_id)
        defer.returnValue(media_info)

    @defer.inlineCallbacks
    def _get_remote_media_impl(self, server_name, media_id):
        media_info = yield self.store.get_cached_remote_media(
            server_name, media_id
        )
        if not media_info:
            media_info = yield self._download_remote_file(
                server_name, media_id
            )
        else:
            self.recently_accessed_remotes.add((server_name, media_id))
            yield self.store.update_cached_last_access_time(
                [(server_name, media_id)], self.clock.time_msec()
            )
        defer.returnValue(media_info)

    @defer.inlineCallbacks
    def _download_remote_file(self, server_name, media_id):
        file_id = random_string(24)

        fname = self.filepaths.remote_media_filepath(
            server_name, file_id
        )
        self._makedirs(fname)

        try:
            with open(fname, "wb") as f:
                request_path = "/".join((
                    "/_matrix/media/v1/download", server_name, media_id,
                ))
                try:
                    length, headers = yield self.client.get_file(
                        server_name, request_path, output_stream=f,
                        max_size=self.max_upload_size,
                    )
                except Exception as e:
                    logger.warn("Failed to fetch remoted media %r", e)
                    raise SynapseError(502, "Failed to fetch remoted media")

            media_type = headers["Content-Type"][0]
            time_now_ms = self.clock.time_msec()

            content_disposition = headers.get("Content-Disposition", None)
            if content_disposition:
                _, params = cgi.parse_header(content_disposition[0],)
                upload_name = None

                # First check if there is a valid UTF-8 filename
                upload_name_utf8 = params.get("filename*", None)
                if upload_name_utf8:
                    if upload_name_utf8.lower().startswith("utf-8''"):
                        upload_name = upload_name_utf8[7:]

                # If there isn't check for an ascii name.
                if not upload_name:
                    upload_name_ascii = params.get("filename", None)
                    if upload_name_ascii and is_ascii(upload_name_ascii):
                        upload_name = upload_name_ascii

                if upload_name:
                    upload_name = urlparse.unquote(upload_name)
                    try:
                        upload_name = upload_name.decode("utf-8")
                    except UnicodeDecodeError:
                        upload_name = None
            else:
                upload_name = None

            logger.info("Stored remote media in file %r", fname)

            yield self.store.store_cached_remote_media(
                origin=server_name,
                media_id=media_id,
                media_type=media_type,
                time_now_ms=self.clock.time_msec(),
                upload_name=upload_name,
                media_length=length,
                filesystem_id=file_id,
            )
        except:
            os.remove(fname)
            raise

        media_info = {
            "media_type": media_type,
            "media_length": length,
            "upload_name": upload_name,
            "created_ts": time_now_ms,
            "filesystem_id": file_id,
        }

        yield self._generate_remote_thumbnails(
            server_name, media_id, media_info
        )

        defer.returnValue(media_info)

    def _get_thumbnail_requirements(self, media_type):
        return self.thumbnail_requirements.get(media_type, ())

    def _generate_thumbnail(self, input_path, t_path, t_width, t_height,
                            t_method, t_type):
        thumbnailer = Thumbnailer(input_path)
        m_width = thumbnailer.width
        m_height = thumbnailer.height

        if m_width * m_height >= self.max_image_pixels:
            logger.info(
                "Image too large to thumbnail %r x %r > %r",
                m_width, m_height, self.max_image_pixels
            )
            return

        if t_method == "crop":
            t_len = thumbnailer.crop(t_path, t_width, t_height, t_type)
        elif t_method == "scale":
            t_len = thumbnailer.scale(t_path, t_width, t_height, t_type)
        else:
            t_len = None

        return t_len

    @defer.inlineCallbacks
    def generate_local_exact_thumbnail(self, media_id, t_width, t_height,
                                       t_method, t_type):
        input_path = self.filepaths.local_media_filepath(media_id)

        t_path = self.filepaths.local_media_thumbnail(
            media_id, t_width, t_height, t_type, t_method
        )
        self._makedirs(t_path)

        t_len = yield preserve_context_over_fn(
            threads.deferToThread,
            self._generate_thumbnail,
            input_path, t_path, t_width, t_height, t_method, t_type
        )

        if t_len:
            yield self.store.store_local_thumbnail(
                media_id, t_width, t_height, t_type, t_method, t_len
            )

            defer.returnValue(t_path)

    @defer.inlineCallbacks
    def generate_remote_exact_thumbnail(self, server_name, file_id, media_id,
                                        t_width, t_height, t_method, t_type):
        input_path = self.filepaths.remote_media_filepath(server_name, file_id)

        t_path = self.filepaths.remote_media_thumbnail(
            server_name, file_id, t_width, t_height, t_type, t_method
        )
        self._makedirs(t_path)

        t_len = yield preserve_context_over_fn(
            threads.deferToThread,
            self._generate_thumbnail,
            input_path, t_path, t_width, t_height, t_method, t_type
        )

        if t_len:
            yield self.store.store_remote_media_thumbnail(
                server_name, media_id, file_id,
                t_width, t_height, t_type, t_method, t_len
            )

            defer.returnValue(t_path)

    @defer.inlineCallbacks
    def _generate_local_thumbnails(self, media_id, media_info):
        media_type = media_info["media_type"]
        requirements = self._get_thumbnail_requirements(media_type)
        if not requirements:
            return

        input_path = self.filepaths.local_media_filepath(media_id)
        thumbnailer = Thumbnailer(input_path)
        m_width = thumbnailer.width
        m_height = thumbnailer.height

        if m_width * m_height >= self.max_image_pixels:
            logger.info(
                "Image too large to thumbnail %r x %r > %r",
                m_width, m_height, self.max_image_pixels
            )
            return

        local_thumbnails = []

        def generate_thumbnails():
            scales = set()
            crops = set()
            for r_width, r_height, r_method, r_type in requirements:
                if r_method == "scale":
                    t_width, t_height = thumbnailer.aspect(r_width, r_height)
                    scales.add((
                        min(m_width, t_width), min(m_height, t_height), r_type,
                    ))
                elif r_method == "crop":
                    crops.add((r_width, r_height, r_type))

            for t_width, t_height, t_type in scales:
                t_method = "scale"
                t_path = self.filepaths.local_media_thumbnail(
                    media_id, t_width, t_height, t_type, t_method
                )
                self._makedirs(t_path)
                t_len = thumbnailer.scale(t_path, t_width, t_height, t_type)

                local_thumbnails.append((
                    media_id, t_width, t_height, t_type, t_method, t_len
                ))

            for t_width, t_height, t_type in crops:
                if (t_width, t_height, t_type) in scales:
                    # If the aspect ratio of the cropped thumbnail matches a purely
                    # scaled one then there is no point in calculating a separate
                    # thumbnail.
                    continue
                t_method = "crop"
                t_path = self.filepaths.local_media_thumbnail(
                    media_id, t_width, t_height, t_type, t_method
                )
                self._makedirs(t_path)
                t_len = thumbnailer.crop(t_path, t_width, t_height, t_type)
                local_thumbnails.append((
                    media_id, t_width, t_height, t_type, t_method, t_len
                ))

        yield preserve_context_over_fn(threads.deferToThread, generate_thumbnails)

        for l in local_thumbnails:
            yield self.store.store_local_thumbnail(*l)

        defer.returnValue({
            "width": m_width,
            "height": m_height,
        })

    @defer.inlineCallbacks
    def _generate_remote_thumbnails(self, server_name, media_id, media_info):
        media_type = media_info["media_type"]
        file_id = media_info["filesystem_id"]
        requirements = self._get_thumbnail_requirements(media_type)
        if not requirements:
            return

        remote_thumbnails = []

        input_path = self.filepaths.remote_media_filepath(server_name, file_id)
        thumbnailer = Thumbnailer(input_path)
        m_width = thumbnailer.width
        m_height = thumbnailer.height

        def generate_thumbnails():
            if m_width * m_height >= self.max_image_pixels:
                logger.info(
                    "Image too large to thumbnail %r x %r > %r",
                    m_width, m_height, self.max_image_pixels
                )
                return

            scales = set()
            crops = set()
            for r_width, r_height, r_method, r_type in requirements:
                if r_method == "scale":
                    t_width, t_height = thumbnailer.aspect(r_width, r_height)
                    scales.add((
                        min(m_width, t_width), min(m_height, t_height), r_type,
                    ))
                elif r_method == "crop":
                    crops.add((r_width, r_height, r_type))

            for t_width, t_height, t_type in scales:
                t_method = "scale"
                t_path = self.filepaths.remote_media_thumbnail(
                    server_name, file_id, t_width, t_height, t_type, t_method
                )
                self._makedirs(t_path)
                t_len = thumbnailer.scale(t_path, t_width, t_height, t_type)
                remote_thumbnails.append([
                    server_name, media_id, file_id,
                    t_width, t_height, t_type, t_method, t_len
                ])

            for t_width, t_height, t_type in crops:
                if (t_width, t_height, t_type) in scales:
                    # If the aspect ratio of the cropped thumbnail matches a purely
                    # scaled one then there is no point in calculating a separate
                    # thumbnail.
                    continue
                t_method = "crop"
                t_path = self.filepaths.remote_media_thumbnail(
                    server_name, file_id, t_width, t_height, t_type, t_method
                )
                self._makedirs(t_path)
                t_len = thumbnailer.crop(t_path, t_width, t_height, t_type)
                remote_thumbnails.append([
                    server_name, media_id, file_id,
                    t_width, t_height, t_type, t_method, t_len
                ])

        yield preserve_context_over_fn(threads.deferToThread, generate_thumbnails)

        for r in remote_thumbnails:
            yield self.store.store_remote_media_thumbnail(*r)

        defer.returnValue({
            "width": m_width,
            "height": m_height,
        })

    @defer.inlineCallbacks
    def delete_old_remote_media(self, before_ts):
        old_media = yield self.store.get_remote_media_before(before_ts)

        deleted = 0

        for media in old_media:
            origin = media["media_origin"]
            media_id = media["media_id"]
            file_id = media["filesystem_id"]
            key = (origin, media_id)

            logger.info("Deleting: %r", key)

            with (yield self.remote_media_linearizer.queue(key)):
                full_path = self.filepaths.remote_media_filepath(origin, file_id)
                try:
                    os.remove(full_path)
                except OSError as e:
                    logger.warn("Failed to remove file: %r", full_path)
                    if e.errno == errno.ENOENT:
                        pass
                    else:
                        continue

                thumbnail_dir = self.filepaths.remote_media_thumbnail_dir(
                    origin, file_id
                )
                shutil.rmtree(thumbnail_dir, ignore_errors=True)

                yield self.store.delete_remote_media(origin, media_id)
                deleted += 1

        defer.returnValue({"deleted": deleted})


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
        Resource.__init__(self)

        media_repo = hs.get_media_repository()

        self.putChild("upload", UploadResource(hs, media_repo))
        self.putChild("download", DownloadResource(hs, media_repo))
        self.putChild("thumbnail", ThumbnailResource(hs, media_repo))
        self.putChild("identicon", IdenticonResource())
        if hs.config.url_preview_enabled:
            self.putChild("preview_url", PreviewUrlResource(hs, media_repo))
