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
from synapse.http.server import respond_with_json, request_handler

from synapse.api.errors import SynapseError

from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer

from twisted.web.resource import Resource

import logging

import sys
import os

logger = logging.getLogger(__name__)


class ShredResource(Resource):
    isLeaf = True

    def __init__(self, hs, media_repo):
        Resource.__init__(self)

        self.media_repo = media_repo
        self.filepaths = media_repo.filepaths
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.auth = hs.get_auth()
        self.max_upload_size = hs.config.max_upload_size
        self.version_string = hs.version_string
        self.clock = hs.get_clock()

    def render_POST(self, request):
        self._async_render_POST(request)
        return NOT_DONE_YET

    def render_OPTIONS(self, request):
        respond_with_json(request, 200, {}, send_cors=True)
        return NOT_DONE_YET

    @request_handler()
    @defer.inlineCallbacks
    def _async_render_POST(self, request):
        server_name, media_id, name = parse_media_id(request)
        if server_name == self.server_name:
            file_path = self.filepaths.local_media_filepath(media_id)
            if (os.system("shred -vu "+file_path) == 0):
                respond_with_json(
                        request, 200, {"message": "successfully shredded "+file_path}, send_cors=True
                        )
            else:
                respond_with_json(
                        request, 503, {"error": "shred invokation returned non-zero status"}, send_cors=True
                        )
        else:
            respond_with_json(
                    request, 401, {"error": "cannot shred remote resource"}, send_cors=True
                    )
