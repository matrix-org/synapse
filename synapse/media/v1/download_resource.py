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

from .base_resource import BaseMediaResource

from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer

import logging

logger = logging.getLogger(__name__)


class DownloadResource(BaseMediaResource):
    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @BaseMediaResource.catch_errors
    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        try:
            server_name, media_id = request.postpath
        except:
            self._respond_404(request)
            return

        if server_name == self.server_name:
            yield self._respond_local_file(request, media_id)
        else:
            yield self._respond_remote_file(request, server_name, media_id)

    @defer.inlineCallbacks
    def _respond_local_file(self, request, media_id):
        media_info = yield self.store.get_local_media(media_id)
        if not media_info:
            self._respond_404(request)
            return

        media_type = media_info["media_type"]
        media_length = media_info["media_length"]
        file_path = self.filepaths.local_media_filepath(media_id)

        yield self._respond_with_file(
            request, media_type, file_path, media_length
        )

    @defer.inlineCallbacks
    def _respond_remote_file(self, request, server_name, media_id):
        media_info = yield self._get_remote_media(server_name, media_id)

        media_type = media_info["media_type"]
        media_length = media_info["media_length"]
        filesystem_id = media_info["filesystem_id"]

        file_path = self.filepaths.remote_media_filepath(
            server_name, filesystem_id
        )

        yield self._respond_with_file(
            request, media_type, file_path, media_length
        )
