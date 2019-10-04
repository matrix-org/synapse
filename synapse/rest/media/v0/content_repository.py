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

import base64
import logging
import os
import re

from canonicaljson import json

from twisted.protocols.basic import FileSender
from twisted.web import resource, server

from synapse.api.errors import Codes, cs_error
from synapse.http.server import finish_request, respond_with_json_bytes

logger = logging.getLogger(__name__)


class ContentRepoResource(resource.Resource):
    """Provides file uploading and downloading.

    Uploads are POSTed to wherever this Resource is linked to. This resource
    returns a "content token" which can be used to GET this content again. The
    token is typically a path, but it may not be. Tokens can expire, be
    one-time uses, etc.

    In this case, the token is a path to the file and contains 3 interesting
    sections:
        - User ID base64d (for namespacing content to each user)
        - random 24 char string
        - Content type base64d (so we can return it when clients GET it)

    """

    isLeaf = True

    def __init__(self, hs, directory):
        resource.Resource.__init__(self)
        self.hs = hs
        self.directory = directory

    def render_GET(self, request):
        # no auth here on purpose, to allow anyone to view, even across home
        # servers.

        # TODO: A little crude here, we could do this better.
        filename = request.path.decode("ascii").split("/")[-1]
        # be paranoid
        filename = re.sub("[^0-9A-z.-_]", "", filename)

        file_path = self.directory + "/" + filename

        logger.debug("Searching for %s", file_path)

        if os.path.isfile(file_path):
            # filename has the content type
            base64_contentype = filename.split(".")[1]
            content_type = base64.urlsafe_b64decode(base64_contentype)
            logger.info("Sending file %s", file_path)
            f = open(file_path, "rb")
            request.setHeader("Content-Type", content_type)

            # cache for at least a day.
            # XXX: we might want to turn this off for data we don't want to
            # recommend caching as it's sensitive or private - or at least
            # select private. don't bother setting Expires as all our matrix
            # clients are smart enough to be happy with Cache-Control (right?)
            request.setHeader(b"Cache-Control", b"public,max-age=86400,s-maxage=86400")

            d = FileSender().beginFileTransfer(f, request)

            # after the file has been sent, clean up and finish the request
            def cbFinished(ignored):
                f.close()
                finish_request(request)

            d.addCallback(cbFinished)
        else:
            respond_with_json_bytes(
                request,
                404,
                json.dumps(cs_error("Not found", code=Codes.NOT_FOUND)),
                send_cors=True,
            )

        return server.NOT_DONE_YET

    def render_OPTIONS(self, request):
        respond_with_json_bytes(request, 200, {}, send_cors=True)
        return server.NOT_DONE_YET
