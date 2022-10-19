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
from typing import IO, TYPE_CHECKING, Dict, List, Optional

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import DirectServeJsonResource, respond_with_json
from synapse.http.servlet import parse_bytes_from_args
from synapse.http.site import SynapseRequest
from synapse.rest.media.v1.media_storage import SpamMediaException

if TYPE_CHECKING:
    from synapse.rest.media.v1.media_repository import MediaRepository
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class UploadResource(DirectServeJsonResource):
    isLeaf = True

    def __init__(self, hs: "HomeServer", media_repo: "MediaRepository"):
        super().__init__()

        self.media_repo = media_repo
        self.filepaths = media_repo.filepaths
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.auth = hs.get_auth()
        self.max_upload_size = hs.config.media.max_upload_size
        self.clock = hs.get_clock()

    async def _async_render_OPTIONS(self, request: SynapseRequest) -> None:
        respond_with_json(request, 200, {}, send_cors=True)

    async def _async_render_POST(self, request: SynapseRequest) -> None:
        requester = await self.auth.get_user_by_req(request)
        raw_content_length = request.getHeader("Content-Length")
        if raw_content_length is None:
            raise SynapseError(msg="Request must specify a Content-Length", code=400)
        try:
            content_length = int(raw_content_length)
        except ValueError:
            raise SynapseError(msg="Content-Length value is invalid", code=400)
        if content_length > self.max_upload_size:
            raise SynapseError(
                msg="Upload request body is too large",
                code=413,
                errcode=Codes.TOO_LARGE,
            )

        args: Dict[bytes, List[bytes]] = request.args  # type: ignore
        upload_name_bytes = parse_bytes_from_args(args, "filename")
        if upload_name_bytes:
            try:
                upload_name: Optional[str] = upload_name_bytes.decode("utf8")
            except UnicodeDecodeError:
                raise SynapseError(
                    msg="Invalid UTF-8 filename parameter: %r" % (upload_name_bytes,),
                    code=400,
                )

        # If the name is falsey (e.g. an empty byte string) ensure it is None.
        else:
            upload_name = None

        headers = request.requestHeaders

        if headers.hasHeader(b"Content-Type"):
            content_type_headers = headers.getRawHeaders(b"Content-Type")
            assert content_type_headers  # for mypy
            media_type = content_type_headers[0].decode("ascii")
        else:
            media_type = "application/octet-stream"

        # if headers.hasHeader(b"Content-Disposition"):
        #     disposition = headers.getRawHeaders(b"Content-Disposition")[0]
        # TODO(markjh): parse content-dispostion

        try:
            content: IO = request.content  # type: ignore
            content_uri = await self.media_repo.create_content(
                media_type, upload_name, content, content_length, requester.user
            )
        except SpamMediaException:
            # For uploading of media we want to respond with a 400, instead of
            # the default 404, as that would just be confusing.
            raise SynapseError(400, "Bad content")

        logger.info("Uploaded content with URI '%s'", content_uri)

        respond_with_json(
            request, 200, {"content_uri": str(content_uri)}, send_cors=True
        )
