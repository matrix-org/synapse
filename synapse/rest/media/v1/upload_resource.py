# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING

from twisted.web.http import Request

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import DirectServeJsonResource, respond_with_json
from synapse.http.servlet import parse_string
from synapse.rest.media.v1.media_storage import SpamMediaException

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer
    from synapse.rest.media.v1.media_repository import MediaRepository

logger = logging.getLogger(__name__)


class UploadResource(DirectServeJsonResource):
    isLeaf = True

    def __init__(self, hs: "HomeServer", media_repo: "MediaRepository"):
        super().__init__()

        self.media_repo = media_repo
        self.filepaths = media_repo.filepaths
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.auth = hs.get_auth()
        self.max_upload_size = hs.config.max_upload_size
        self.clock = hs.get_clock()

    async def _async_render_OPTIONS(self, request: Request) -> None:
        respond_with_json(request, 200, {}, send_cors=True)

    async def _async_render_POST(self, request: Request) -> None:
        requester = await self.auth.get_user_by_req(request)
        # TODO: The checks here are a bit late. The content will have
        # already been uploaded to a tmp file at this point
        content_length = request.getHeader("Content-Length")
        if content_length is None:
            raise SynapseError(msg="Request must specify a Content-Length", code=400)
        if int(content_length) > self.max_upload_size:
            raise SynapseError(
                msg="Upload request body is too large",
                code=413,
                errcode=Codes.TOO_LARGE,
            )

        upload_name = parse_string(request, b"filename", encoding=None)
        if upload_name:
            try:
                upload_name = upload_name.decode("utf8")
            except UnicodeDecodeError:
                raise SynapseError(
                    msg="Invalid UTF-8 filename parameter: %r" % (upload_name), code=400
                )

        # If the name is falsey (e.g. an empty byte string) ensure it is None.
        else:
            upload_name = None

        headers = request.requestHeaders

        if headers.hasHeader(b"Content-Type"):
            media_type = headers.getRawHeaders(b"Content-Type")[0].decode("ascii")
        else:
            raise SynapseError(msg="Upload request missing 'Content-Type'", code=400)

        # if headers.hasHeader(b"Content-Disposition"):
        #     disposition = headers.getRawHeaders(b"Content-Disposition")[0]
        # TODO(markjh): parse content-dispostion

        try:
            content_uri = await self.media_repo.create_content(
                media_type, upload_name, request.content, content_length, requester.user
            )
        except SpamMediaException:
            # For uploading of media we want to respond with a 400, instead of
            # the default 404, as that would just be confusing.
            raise SynapseError(400, "Bad content")

        logger.info("Uploaded content with URI %r", content_uri)

        respond_with_json(request, 200, {"content_uri": content_uri}, send_cors=True)
