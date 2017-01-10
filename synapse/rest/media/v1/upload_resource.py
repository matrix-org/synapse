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

from synapse.http.server import respond_with_json, request_handler

from synapse.api.errors import SynapseError

from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer

from twisted.web.resource import Resource

import logging

logger = logging.getLogger(__name__)


class UploadResource(Resource):
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
        requester = yield self.auth.get_user_by_req(request)
        # TODO: The checks here are a bit late. The content will have
        # already been uploaded to a tmp file at this point
        content_length = request.getHeader("Content-Length")
        if content_length is None:
            raise SynapseError(
                msg="Request must specify a Content-Length", code=400
            )
        if int(content_length) > self.max_upload_size:
            raise SynapseError(
                msg="Upload request body is too large",
                code=413,
            )

        upload_name = request.args.get("filename", None)
        if upload_name:
            try:
                upload_name = upload_name[0].decode('UTF-8')
            except UnicodeDecodeError:
                raise SynapseError(
                    msg="Invalid UTF-8 filename parameter: %r" % (upload_name),
                    code=400,
                )

        headers = request.requestHeaders

        if headers.hasHeader("Content-Type"):
            media_type = headers.getRawHeaders("Content-Type")[0]
        else:
            raise SynapseError(
                msg="Upload request missing 'Content-Type'",
                code=400,
            )

        # if headers.hasHeader("Content-Disposition"):
        #     disposition = headers.getRawHeaders("Content-Disposition")[0]
        # TODO(markjh): parse content-dispostion

        content_uri = yield self.media_repo.create_content(
            media_type, upload_name, request.content.read(),
            content_length, requester.user
        )

        logger.info("Uploaded content with URI %r", content_uri)

        respond_with_json(
            request, 200, {"content_uri": content_uri}, send_cors=True
        )
