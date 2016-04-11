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

from .thumbnailer import Thumbnailer

from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.http.server import respond_with_json, finish_request
from synapse.util.stringutils import random_string
from synapse.api.errors import (
    cs_error, Codes, SynapseError
)

from twisted.internet import defer, threads
from twisted.web.resource import Resource
from twisted.protocols.basic import FileSender

from synapse.util.async import ObservableDeferred
from synapse.util.stringutils import is_ascii
from synapse.util.logcontext import preserve_context_over_fn

import os

import cgi
import logging
import urllib
import urlparse

logger = logging.getLogger(__name__)


def parse_media_id(request):
    try:
        # This allows users to append e.g. /test.png to the URL. Useful for
        # clients that parse the URL to see content type.
        server_name, media_id = request.postpath[:2]
        file_name = None
        if len(request.postpath) > 2:
            try:
                file_name = urlparse.unquote(request.postpath[-1]).decode("utf-8")
            except UnicodeDecodeError:
                pass
        return server_name, media_id, file_name
    except:
        raise SynapseError(
            404,
            "Invalid media id token %r" % (request.postpath,),
            Codes.UNKNOWN,
        )


class BaseMediaResource(Resource):
    isLeaf = True

    def __init__(self, hs, filepaths):
        Resource.__init__(self)
        self.auth = hs.get_auth()
        self.client = MatrixFederationHttpClient(hs)
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.max_upload_size = hs.config.max_upload_size
        self.max_image_pixels = hs.config.max_image_pixels
        self.max_spider_size = hs.config.max_spider_size
        self.filepaths = filepaths
        self.version_string = hs.version_string
        self.downloads = {}
        self.dynamic_thumbnails = hs.config.dynamic_thumbnails
        self.thumbnail_requirements = hs.config.thumbnail_requirements

    def _respond_404(self, request):
        respond_with_json(
            request, 404,
            cs_error(
                "Not found %r" % (request.postpath,),
                code=Codes.NOT_FOUND,
            ),
            send_cors=True
        )

    @staticmethod
    def _makedirs(filepath):
        dirname = os.path.dirname(filepath)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

    def _get_remote_media(self, server_name, media_id):
        key = (server_name, media_id)
        download = self.downloads.get(key)
        if download is None:
            download = self._get_remote_media_impl(server_name, media_id)
            download = ObservableDeferred(
                download,
                consumeErrors=True
            )
            self.downloads[key] = download

            @download.addBoth
            def callback(media_info):
                del self.downloads[key]
                return media_info
        return download.observe()

    @defer.inlineCallbacks
    def _get_remote_media_impl(self, server_name, media_id):
        media_info = yield self.store.get_cached_remote_media(
            server_name, media_id
        )
        if not media_info:
            media_info = yield self._download_remote_file(
                server_name, media_id
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
                length, headers = yield self.client.get_file(
                    server_name, request_path, output_stream=f,
                    max_size=self.max_upload_size,
                )
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

    @defer.inlineCallbacks
    def _respond_with_file(self, request, media_type, file_path,
                           file_size=None, upload_name=None):
        logger.debug("Responding with %r", file_path)

        if os.path.isfile(file_path):
            request.setHeader(b"Content-Type", media_type.encode("UTF-8"))
            if upload_name:
                if is_ascii(upload_name):
                    request.setHeader(
                        b"Content-Disposition",
                        b"inline; filename=%s" % (
                            urllib.quote(upload_name.encode("utf-8")),
                        ),
                    )
                else:
                    request.setHeader(
                        b"Content-Disposition",
                        b"inline; filename*=utf-8''%s" % (
                            urllib.quote(upload_name.encode("utf-8")),
                        ),
                    )

            # cache for at least a day.
            # XXX: we might want to turn this off for data we don't want to
            # recommend caching as it's sensitive or private - or at least
            # select private. don't bother setting Expires as all our
            # clients are smart enough to be happy with Cache-Control
            request.setHeader(
                b"Cache-Control", b"public,max-age=86400,s-maxage=86400"
            )
            if file_size is None:
                stat = os.stat(file_path)
                file_size = stat.st_size

            request.setHeader(
                b"Content-Length", b"%d" % (file_size,)
            )

            with open(file_path, "rb") as f:
                yield FileSender().beginFileTransfer(f, request)

            finish_request(request)
        else:
            self._respond_404(request)

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
    def _generate_local_exact_thumbnail(self, media_id, t_width, t_height,
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
    def _generate_remote_exact_thumbnail(self, server_name, file_id, media_id,
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
