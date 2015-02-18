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

from .thumbnailer import Thumbnailer

from synapse.http.server import respond_with_json
from synapse.util.stringutils import random_string
from synapse.api.errors import (
    cs_exception, CodeMessageException, cs_error, Codes, SynapseError
)

from twisted.internet import defer
from twisted.web.resource import Resource
from twisted.protocols.basic import FileSender

import os

import logging

logger = logging.getLogger(__name__)


class BaseMediaResource(Resource):
    isLeaf = True

    def __init__(self, hs, filepaths):
        Resource.__init__(self)
        self.auth = hs.get_auth()
        self.client = hs.get_http_client()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.max_upload_size = hs.config.max_upload_size
        self.max_image_pixels = hs.config.max_image_pixels
        self.filepaths = filepaths
        self.downloads = {}

    @staticmethod
    def catch_errors(request_handler):
        @defer.inlineCallbacks
        def wrapped_request_handler(self, request):
            try:
                yield request_handler(self, request)
            except CodeMessageException as e:
                logger.info("Responding with error: %r", e)
                respond_with_json(
                    request, e.code, cs_exception(e), send_cors=True
                )
            except:
                logger.exception(
                    "Failed handle request %s.%s on %r",
                    request_handler.__module__,
                    request_handler.__name__,
                    self,
                )
                respond_with_json(
                    request,
                    500,
                    {"error": "Internal server error"},
                    send_cors=True
                )
        return wrapped_request_handler

    @staticmethod
    def _parse_media_id(request):
        try:
            server_name, media_id = request.postpath
            return (server_name, media_id)
        except:
            raise SynapseError(
                404,
                "Invalid media id token %r" % (request.postpath,),
                Codes.UNKNOWN,
            )

    @staticmethod
    def _parse_integer(request, arg_name, default=None):
        try:
            if default is None:
                return int(request.args[arg_name][0])
            else:
                return int(request.args.get(arg_name, [default])[0])
        except:
            raise SynapseError(
                400,
                "Missing integer argument %r" % (arg_name,),
                Codes.UNKNOWN,
            )

    @staticmethod
    def _parse_string(request, arg_name, default=None):
        try:
            if default is None:
                return request.args[arg_name][0]
            else:
                return request.args.get(arg_name, [default])[0]
        except:
            raise SynapseError(
                400,
                "Missing string argument %r" % (arg_name,),
                Codes.UNKNOWN,
            )

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
            self.downloads[key] = download

            @download.addBoth
            def callback(media_info):
                del self.downloads[key]
                return media_info
        return download

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

            yield self.store.store_cached_remote_media(
                origin=server_name,
                media_id=media_id,
                media_type=media_type,
                time_now_ms=self.clock.time_msec(),
                upload_name=None,
                media_length=length,
                filesystem_id=file_id,
            )
        except:
            os.remove(fname)
            raise

        media_info = {
            "media_type": media_type,
            "media_length": length,
            "upload_name": None,
            "created_ts": time_now_ms,
            "filesystem_id": file_id,
        }

        yield self._generate_remote_thumbnails(
            server_name, media_id, media_info
        )

        defer.returnValue(media_info)

    @defer.inlineCallbacks
    def _respond_with_file(self, request, media_type, file_path,
                           file_size=None):
        logger.debug("Responding with %r", file_path)

        if os.path.isfile(file_path):
            request.setHeader(b"Content-Type", media_type.encode("UTF-8"))

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

            request.finish()
        else:
            self._respond_404(request)

    def _get_thumbnail_requirements(self, media_type):
        if media_type == "image/jpeg":
            return (
                (32, 32, "crop", "image/jpeg"),
                (96, 96, "crop", "image/jpeg"),
                (320, 240, "scale", "image/jpeg"),
                (640, 480, "scale", "image/jpeg"),
            )
        elif (media_type == "image/png") or (media_type == "image/gif"):
            return (
                (32, 32, "crop", "image/png"),
                (96, 96, "crop", "image/png"),
                (320, 240, "scale", "image/png"),
                (640, 480, "scale", "image/png"),
            )
        else:
            return ()

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
            yield self.store.store_local_thumbnail(
                media_id, t_width, t_height, t_type, t_method, t_len
            )

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
            yield self.store.store_local_thumbnail(
                media_id, t_width, t_height, t_type, t_method, t_len
            )

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

        input_path = self.filepaths.remote_media_filepath(server_name, file_id)
        thumbnailer = Thumbnailer(input_path)
        m_width = thumbnailer.width
        m_height = thumbnailer.height

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
            yield self.store.store_remote_media_thumbnail(
                server_name, media_id, file_id,
                t_width, t_height, t_type, t_method, t_len
            )

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
            yield self.store.store_remote_media_thumbnail(
                server_name, media_id, file_id,
                t_width, t_height, t_type, t_method, t_len
            )

        defer.returnValue({
            "width": m_width,
            "height": m_height,
        })
