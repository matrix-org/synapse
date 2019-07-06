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

import logging

from twisted.web.server import NOT_DONE_YET

from synapse.api.errors import SynapseError
from synapse.http.server import (
    DirectServeResource,
    respond_with_json,
    wrap_json_request_handler,
)
from synapse.http.servlet import parse_string

logger = logging.getLogger(__name__)


class UploadResource(DirectServeResource):
    isLeaf = True

    def __init__(self, hs, media_repo):
        super().__init__()

        self.media_repo = media_repo
        self.filepaths = media_repo.filepaths
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.auth = hs.get_auth()
        self.max_upload_size = hs.config.max_upload_size
        self.clock = hs.get_clock()

    def render_OPTIONS(self, request):
        respond_with_json(request, 200, {}, send_cors=True)
        return NOT_DONE_YET

    @wrap_json_request_handler
    async def _async_render_POST(self, request):
        requester = await self.auth.get_user_by_req(request)
        # TODO: The checks here are a bit late. The content will have
        # already been uploaded to a tmp file at this point
        content_length = request.getHeader(b"Content-Length").decode("ascii")
        if content_length is None:
            raise SynapseError(msg="Request must specify a Content-Length", code=400)
        if int(content_length) > self.max_upload_size:
            raise SynapseError(msg="Upload request body is too large", code=413)

        upload_name = parse_string(request, b"filename", encoding=None)
        if upload_name:
            try:
                upload_name = upload_name.decode("utf8")
            except UnicodeDecodeError:
                raise SynapseError(
                    msg="Invalid UTF-8 filename parameter: %r" % (upload_name), code=400
                )

        headers = request.requestHeaders

        if headers.hasHeader(b"Content-Type"):
            media_type = headers.getRawHeaders(b"Content-Type")[0].decode("ascii")
        else:
            raise SynapseError(msg="Upload request missing 'Content-Type'", code=400)

        # if headers.hasHeader(b"Content-Disposition"):
        #     disposition = headers.getRawHeaders(b"Content-Disposition")[0]
        # TODO(markjh): parse content-dispostion

        content_uri = await self.media_repo.create_content(
            media_type, upload_name, request.content, content_length, requester.user
        )

        logger.info("Uploaded content with URI %r", content_uri)

        respond_with_json(request, 200, {"content_uri": content_uri}, send_cors=True)
