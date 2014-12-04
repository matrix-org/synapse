# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from synapse.http.server import respond_with_json
from synapse.util.stringutils import random_string
from synapse.api.errors import (
    cs_exception, CodeMessageException, cs_error, Codes
)

from twisted.protocols.basic import FileSender
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer

import os

import logging

logger = logging.getLogger(__name__)


class DownloadResource(Resource):
    isLeaf = True

    def __init__(self, hs, filepaths):
        Resource.__init__(self)
        self.client = hs.get_http_client()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.filepaths = filepaths

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    def _respond_404(self, request):
        respond_with_json(
            request, 404,
            cs_error(
                "Not found %r" % (request.postpath,),
                code=Codes.NOT_FOUND,
            ),
            send_cors=True
        )

    @defer.inlineCallbacks
    def _async_render_GET(self, request):

        try:
            server_name, media_id = request.postpath
        except:
            self._respond_404(request)
            return

        try:
            if server_name == self.server_name:
                yield self._respond_local_file(request, media_id)
            else:
                yield self._respond_remote_file(request, server_name, media_id)
        except CodeMessageException as e:
            logger.exception(e)
            respond_with_json(request, e.code, cs_exception(e), send_cors=True)
        except:
            logger.exception("Failed to serve file")
            respond_with_json(
                request,
                500,
                {"error": "Internal server error"},
                send_cors=True
            )

    @defer.inlineCallbacks
    def _download_remote_file(self, server_name, media_id):
        filesystem_id = random_string(24)

        fname = self.filepaths.remote_media_filepath(
            server_name, filesystem_id
        )
        os.makedirs(os.path.dirname(fname))

        try:
            with open(fname, "wb") as f:
                length, headers = yield self.client.get_file(
                    server_name,
                    "/".join((
                        "/_matrix/media/v1/download", server_name, media_id,
                    )),
                    output_stream=f,
                )
        except:
            os.remove(fname)
            raise

        media_type = headers["Content-Type"][0]
        time_now_ms = self.clock.time_msec()

        yield self.store.store_cached_remote_media(
            origin=server_name,
            media_id=media_id,
            media_type=media_type,
            time_now_ms=self.clock.time_msec(),
            upload_name=None,
            media_length=length,
            filesystem_id=filesystem_id,
        )

        defer.returnValue({
            "media_type": media_type,
            "media_length": length,
            "upload_name": None,
            "created_ts": time_now_ms,
            "filesystem_id": filesystem_id,
        })

    @defer.inlineCallbacks
    def _respond_remote_file(self, request, server_name, media_id):
        media_info = yield self.store.get_cached_remote_media(
            server_name, media_id
        )

        if not media_info:
            media_info = yield self._download_remote_file(
                server_name, media_id
            )

        filesystem_id = media_info["filesystem_id"]

        file_path = self.filepaths.remote_media_filepath(
            server_name, filesystem_id
        )

        if os.path.isfile(file_path):
            media_type = media_info["media_type"]
            request.setHeader(b"Content-Type", media_type.encode("UTF-8"))

            # cache for at least a day.
            # XXX: we might want to turn this off for data we don't want to
            # recommend caching as it's sensitive or private - or at least
            # select private. don't bother setting Expires as all our
            # clients are smart enough to be happy with Cache-Control
            request.setHeader(
                b"Cache-Control", b"public,max-age=86400,s-maxage=86400"
            )

            with open(file_path, "rb") as f:
                yield FileSender().beginFileTransfer(f, request)

            request.finish()
        else:
            self._respond_404()

    @defer.inlineCallbacks
    def _respond_local_file(self, request, media_id):
        media_info = yield self.store.get_local_media(media_id)
        if not media_info:
            self._respond_404()
            return

        file_path = self.filepaths.local_media_filepath(media_id)

        logger.debug("Searching for %s", file_path)

        if os.path.isfile(file_path):
            media_type = media_info["media_type"]
            request.setHeader(b"Content-Type", media_type.encode("UTF-8"))

            # cache for at least a day.
            # XXX: we might want to turn this off for data we don't want to
            # recommend caching as it's sensitive or private - or at least
            # select private. don't bother setting Expires as all our
            # clients are smart enough to be happy with Cache-Control
            request.setHeader(
                b"Cache-Control", b"public,max-age=86400,s-maxage=86400"
            )

            with open(file_path, "rb") as f:
                yield FileSender().beginFileTransfer(f, request)

            request.finish()
        else:
            self._respond_404()
