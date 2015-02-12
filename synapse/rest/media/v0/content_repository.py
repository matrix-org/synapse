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

from synapse.http.server import respond_with_json_bytes

from synapse.util.stringutils import random_string
from synapse.api.errors import (
    cs_exception, SynapseError, CodeMessageException, Codes, cs_error
)

from twisted.protocols.basic import FileSender
from twisted.web import server, resource
from twisted.internet import defer

import base64
import simplejson as json
import logging
import os
import re

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

    def __init__(self, hs, directory, auth, external_addr):
        resource.Resource.__init__(self)
        self.hs = hs
        self.directory = directory
        self.auth = auth
        self.external_addr = external_addr.rstrip('/')
        self.max_upload_size = hs.config.max_upload_size

        if not os.path.isdir(self.directory):
            os.mkdir(self.directory)
            logger.info("ContentRepoResource : Created %s directory.",
                        self.directory)

    @defer.inlineCallbacks
    def map_request_to_name(self, request):
        # auth the user
        auth_user, client = yield self.auth.get_user_by_req(request)

        # namespace all file uploads on the user
        prefix = base64.urlsafe_b64encode(
            auth_user.to_string()
        ).replace('=', '')

        # use a random string for the main portion
        main_part = random_string(24)

        # suffix with a file extension if we can make one. This is nice to
        # provide a hint to clients on the file information. We will also reuse
        # this info to spit back the content type to the client.
        suffix = ""
        if request.requestHeaders.hasHeader("Content-Type"):
            content_type = request.requestHeaders.getRawHeaders(
                "Content-Type")[0]
            suffix = "." + base64.urlsafe_b64encode(content_type)
            if (content_type.split("/")[0].lower() in
                    ["image", "video", "audio"]):
                file_ext = content_type.split("/")[-1]
                # be a little paranoid and only allow a-z
                file_ext = re.sub("[^a-z]", "", file_ext)
                suffix += "." + file_ext

        file_name = prefix + main_part + suffix
        file_path = os.path.join(self.directory, file_name)
        logger.info("User %s is uploading a file to path %s",
                    auth_user.to_string(),
                    file_path)

        # keep trying to make a non-clashing file, with a sensible max attempts
        attempts = 0
        while os.path.exists(file_path):
            main_part = random_string(24)
            file_name = prefix + main_part + suffix
            file_path = os.path.join(self.directory, file_name)
            attempts += 1
            if attempts > 25:  # really? Really?
                raise SynapseError(500, "Unable to create file.")

        defer.returnValue(file_path)

    def render_GET(self, request):
        # no auth here on purpose, to allow anyone to view, even across home
        # servers.

        # TODO: A little crude here, we could do this better.
        filename = request.path.split('/')[-1]
        # be paranoid
        filename = re.sub("[^0-9A-z.-_]", "", filename)

        file_path = self.directory + "/" + filename

        logger.debug("Searching for %s", file_path)

        if os.path.isfile(file_path):
            # filename has the content type
            base64_contentype = filename.split(".")[1]
            content_type = base64.urlsafe_b64decode(base64_contentype)
            logger.info("Sending file %s", file_path)
            f = open(file_path, 'rb')
            request.setHeader('Content-Type', content_type)

            # cache for at least a day.
            # XXX: we might want to turn this off for data we don't want to
            # recommend caching as it's sensitive or private - or at least
            # select private. don't bother setting Expires as all our matrix
            # clients are smart enough to be happy with Cache-Control (right?)
            request.setHeader(
                "Cache-Control", "public,max-age=86400,s-maxage=86400"
            )

            d = FileSender().beginFileTransfer(f, request)

            # after the file has been sent, clean up and finish the request
            def cbFinished(ignored):
                f.close()
                request.finish()
            d.addCallback(cbFinished)
        else:
            respond_with_json_bytes(
                request,
                404,
                json.dumps(cs_error("Not found", code=Codes.NOT_FOUND)),
                send_cors=True)

        return server.NOT_DONE_YET

    def render_POST(self, request):
        self._async_render(request)
        return server.NOT_DONE_YET

    def render_OPTIONS(self, request):
        respond_with_json_bytes(request, 200, {}, send_cors=True)
        return server.NOT_DONE_YET

    @defer.inlineCallbacks
    def _async_render(self, request):
        try:
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

            fname = yield self.map_request_to_name(request)

            # TODO I have a suspicious feeling this is just going to block
            with open(fname, "wb") as f:
                f.write(request.content.read())

            # FIXME (erikj): These should use constants.
            file_name = os.path.basename(fname)
            # FIXME: we can't assume what the repo's public mounted path is
            # ...plus self-signed SSL won't work to remote clients anyway
            # ...and we can't assume that it's SSL anyway, as we might want to
            # serve it via the non-SSL listener...
            url = "%s/_matrix/content/%s" % (
                self.external_addr, file_name
            )

            respond_with_json_bytes(request, 200,
                                    json.dumps({"content_token": url}),
                                    send_cors=True)

        except CodeMessageException as e:
            logger.exception(e)
            respond_with_json_bytes(request, e.code,
                                    json.dumps(cs_exception(e)))
        except Exception as e:
            logger.error("Failed to store file: %s" % e)
            respond_with_json_bytes(
                request,
                500,
                json.dumps({"error": "Internal server error"}),
                send_cors=True)
