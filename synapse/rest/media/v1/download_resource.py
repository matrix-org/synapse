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

from ._base import parse_media_id, respond_with_file, respond_404
from twisted.web.resource import Resource
from synapse.http.server import request_handler, set_cors_headers

from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer

import logging

logger = logging.getLogger(__name__)


class DownloadResource(Resource):
    isLeaf = True

    def __init__(self, hs, media_repo):
        Resource.__init__(self)

        self.filepaths = media_repo.filepaths
        self.media_repo = media_repo
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.version_string = hs.version_string
        self.clock = hs.get_clock()

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @request_handler()
    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        set_cors_headers(request)
        request.setHeader(
            "Content-Security-Policy",
            "default-src 'none';"
            " script-src 'none';"
            " plugin-types application/pdf;"
            " style-src 'unsafe-inline';"
            " object-src 'self';"
        )
        server_name, media_id, name = parse_media_id(request)
        if server_name == self.server_name:
            yield self._respond_local_file(request, media_id, name)
        else:
            yield self._respond_remote_file(
                request, server_name, media_id, name
            )

    @defer.inlineCallbacks
    def _respond_local_file(self, request, media_id, name):
        media_info = yield self.store.get_local_media(media_id)
        if not media_info:
            respond_404(request)
            return

        media_type = media_info["media_type"]
        media_length = media_info["media_length"]
        upload_name = name if name else media_info["upload_name"]
        file_path = self.filepaths.local_media_filepath(media_id)

        yield respond_with_file(
            request, media_type, file_path, media_length,
            upload_name=upload_name,
        )

    @defer.inlineCallbacks
    def _respond_remote_file(self, request, server_name, media_id, name):
        media_info = yield self.media_repo.get_remote_media(server_name, media_id)

        media_type = media_info["media_type"]
        media_length = media_info["media_length"]
        filesystem_id = media_info["filesystem_id"]
        upload_name = name if name else media_info["upload_name"]

        file_path = self.filepaths.remote_media_filepath(
            server_name, filesystem_id
        )

        yield respond_with_file(
            request, media_type, file_path, media_length,
            upload_name=upload_name,
        )
