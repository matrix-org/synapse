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

from synapse.http.server import respond_with_json

from synapse.util.stringutils import random_string
from synapse.api.errors import (
    cs_exception, SynapseError, CodeMessageException
)

from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer

from .base_resource import BaseMediaResource

import logging

logger = logging.getLogger(__name__)


class UploadResource(BaseMediaResource):
    def render_POST(self, request):
        self._async_render_POST(request)
        return NOT_DONE_YET

    def render_OPTIONS(self, request):
        respond_with_json(request, 200, {}, send_cors=True)
        return NOT_DONE_YET

    @defer.inlineCallbacks
    def create_content(self, media_type, upload_name, content, content_length,
                       auth_user):
        media_id = random_string(24)

        fname = self.filepaths.local_media_filepath(media_id)
        self._makedirs(fname)

        # This shouldn't block for very long because the content will have
        # already been uploaded at this point.
        with open(fname, "wb") as f:
            f.write(content)

        yield self.store.store_local_media(
            media_id=media_id,
            media_type=media_type,
            time_now_ms=self.clock.time_msec(),
            upload_name=upload_name,
            media_length=content_length,
            user_id=auth_user,
        )
        media_info = {
            "media_type": media_type,
            "media_length": content_length,
        }

        yield self._generate_local_thumbnails(media_id, media_info)

        defer.returnValue("mxc://%s/%s" % (self.server_name, media_id))

    @defer.inlineCallbacks
    def _async_render_POST(self, request):
        try:
            auth_user, client = yield self.auth.get_user_by_req(request)
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

            content_uri = yield self.create_content(
                media_type, None, request.content.read(),
                content_length, auth_user
            )

            respond_with_json(
                request, 200, {"content_uri": content_uri}, send_cors=True
            )
        except CodeMessageException as e:
            logger.exception(e)
            respond_with_json(request, e.code, cs_exception(e), send_cors=True)
        except:
            logger.exception("Failed to store file")
            respond_with_json(
                request,
                500,
                {"error": "Internal server error"},
                send_cors=True
            )
