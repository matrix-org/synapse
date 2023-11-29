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
import re
from typing import IO, TYPE_CHECKING, Dict, List, Optional, Tuple

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import respond_with_json
from synapse.http.servlet import RestServlet, parse_bytes_from_args
from synapse.http.site import SynapseRequest
from synapse.media.media_storage import SpamMediaException

if TYPE_CHECKING:
    from synapse.media.media_repository import MediaRepository
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# The name of the lock to use when uploading media.
_UPLOAD_MEDIA_LOCK_NAME = "upload_media"


class BaseUploadServlet(RestServlet):
    def __init__(self, hs: "HomeServer", media_repo: "MediaRepository"):
        super().__init__()

        self.media_repo = media_repo
        self.filepaths = media_repo.filepaths
        self.store = hs.get_datastores().main
        self.server_name = hs.hostname
        self.auth = hs.get_auth()
        self.max_upload_size = hs.config.media.max_upload_size

    def _get_file_metadata(
        self, request: SynapseRequest
    ) -> Tuple[int, Optional[str], str]:
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

        return content_length, upload_name, media_type


class UploadServlet(BaseUploadServlet):
    PATTERNS = [re.compile("/_matrix/media/(r0|v3|v1)/upload$")]

    async def on_POST(self, request: SynapseRequest) -> None:
        requester = await self.auth.get_user_by_req(request)
        content_length, upload_name, media_type = self._get_file_metadata(request)

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


class AsyncUploadServlet(BaseUploadServlet):
    PATTERNS = [
        re.compile(
            "/_matrix/media/v3/upload/(?P<server_name>[^/]*)/(?P<media_id>[^/]*)$"
        )
    ]

    async def on_PUT(
        self, request: SynapseRequest, server_name: str, media_id: str
    ) -> None:
        requester = await self.auth.get_user_by_req(request)

        if server_name != self.server_name:
            raise SynapseError(
                404,
                "Non-local server name specified",
                errcode=Codes.NOT_FOUND,
            )

        lock = await self.store.try_acquire_lock(_UPLOAD_MEDIA_LOCK_NAME, media_id)
        if not lock:
            raise SynapseError(
                409,
                "Media ID cannot be overwritten",
                errcode=Codes.CANNOT_OVERWRITE_MEDIA,
            )

        async with lock:
            await self.media_repo.verify_can_upload(media_id, requester.user)
            content_length, upload_name, media_type = self._get_file_metadata(request)

            try:
                content: IO = request.content  # type: ignore
                await self.media_repo.update_content(
                    media_id,
                    media_type,
                    upload_name,
                    content,
                    content_length,
                    requester.user,
                )
            except SpamMediaException:
                # For uploading of media we want to respond with a 400, instead of
                # the default 404, as that would just be confusing.
                raise SynapseError(400, "Bad content")

            logger.info("Uploaded content for media ID %r", media_id)
            respond_with_json(request, 200, {}, send_cors=True)
