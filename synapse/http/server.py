# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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


from syutil.jsonutil import (
    encode_canonical_json, encode_pretty_printed_json
)
from synapse.api.errors import (
    cs_exception, SynapseError, CodeMessageException, Codes, cs_error
)
from synapse.util.stringutils import random_string

from twisted.internet import defer, reactor
from twisted.protocols.basic import FileSender
from twisted.web import server, resource
from twisted.web.server import NOT_DONE_YET
from twisted.web.util import redirectTo

import base64
import collections
import json
import logging
import os
import re

logger = logging.getLogger(__name__)


class HttpServer(object):
    """ Interface for registering callbacks on a HTTP server
    """

    def register_path(self, method, path_pattern, callback):
        """ Register a callback that get's fired if we receive a http request
        with the given method for a path that matches the given regex.

        If the regex contains groups these get's passed to the calback via
        an unpacked tuple.

        Args:
            method (str): The method to listen to.
            path_pattern (str): The regex used to match requests.
            callback (function): The function to fire if we receive a matched
                request. The first argument will be the request object and
                subsequent arguments will be any matched groups from the regex.
                This should return a tuple of (code, response).
        """
        pass


class JsonResource(HttpServer, resource.Resource):
    """ This implements the HttpServer interface and provides JSON support for
    Resources.

    Register callbacks via register_path()
    """

    isLeaf = True

    _PathEntry = collections.namedtuple("_PathEntry", ["pattern", "callback"])

    def __init__(self):
        resource.Resource.__init__(self)

        self.path_regexs = {}

    def register_path(self, method, path_pattern, callback):
        self.path_regexs.setdefault(method, []).append(
            self._PathEntry(path_pattern, callback)
        )

    def start_listening(self, port):
        """ Registers the http server with the twisted reactor.

        Args:
            port (int): The port to listen on.

        """
        reactor.listenTCP(port, server.Site(self))

    # Gets called by twisted
    def render(self, request):
        """ This get's called by twisted every time someone sends us a request.
        """
        self._async_render(request)
        return server.NOT_DONE_YET

    @defer.inlineCallbacks
    def _async_render(self, request):
        """ This get's called by twisted every time someone sends us a request.
            This checks if anyone has registered a callback for that method and
            path.
        """
        try:
            # Just say yes to OPTIONS.
            if request.method == "OPTIONS":
                self._send_response(request, 200, {})
                return

            # Loop through all the registered callbacks to check if the method
            # and path regex match
            for path_entry in self.path_regexs.get(request.method, []):
                m = path_entry.pattern.match(request.path)
                if m:
                    # We found a match! Trigger callback and then return the
                    # returned response. We pass both the request and any
                    # matched groups from the regex to the callback.
                    code, response = yield path_entry.callback(
                        request,
                        *m.groups()
                    )

                    self._send_response(request, code, response)
                    return

            # Huh. No one wanted to handle that? Fiiiiiine. Send 400.
            self._send_response(
                request,
                400,
                {"error": "Unrecognized request"}
            )
        except CodeMessageException as e:
            logger.exception(e)
            self._send_response(
                request,
                e.code,
                cs_exception(e)
            )
        except Exception as e:
            logger.exception(e)
            self._send_response(
                request,
                500,
                {"error": "Internal server error"}
            )

    def _send_response(self, request, code, response_json_object):

        if not self._request_user_agent_is_curl(request):
            json_bytes = encode_canonical_json(response_json_object)
        else:
            json_bytes = encode_pretty_printed_json(response_json_object)

        # TODO: Only enable CORS for the requests that need it.
        respond_with_json_bytes(request, code, json_bytes, send_cors=True)

    @staticmethod
    def _request_user_agent_is_curl(request):
        user_agents = request.requestHeaders.getRawHeaders(
            "User-Agent", default=[]
        )
        for user_agent in user_agents:
            if "curl" in user_agent:
                return True
        return False


class RootRedirect(resource.Resource):
    """Redirects the root '/' path to another path."""

    def __init__(self, path):
        resource.Resource.__init__(self)
        self.url = path

    def render_GET(self, request):
        return redirectTo(self.url, request)

    def getChild(self, name, request):
        if len(name) == 0:
            return self  # select ourselves as the child to render
        return resource.Resource.getChild(self, name, request)


class ContentRepoResource(resource.Resource):
    """Provides file uploading and downloading.

    Uploads are POSTed to wherever this Resource is linked to. This resource
    returns a "content token" which can be used to GET this content again. The
    token is typically a path, but it may not be.

    In this case, the token contains 3 sections:
        - User ID base64d (for namespacing content to each user)
        - random string
        - Content type base64d (so we can return it when clients GET it)

    """
    isLeaf = True

    def __init__(self, directory, auth):
        resource.Resource.__init__(self)
        self.directory = directory
        self.auth = auth

        if not os.path.isdir(self.directory):
            os.mkdir(self.directory)
            logger.info("FileUploadResource : Created %s directory.",
                        self.directory)

    @defer.inlineCallbacks
    def map_request_to_name(self, request):
        # auth the user
        auth_user = yield self.auth.get_user_by_req(request)

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

        file_path = os.path.join(self.directory, prefix + main_part + suffix)
        logger.info("User %s is uploading a file to path %s",
                    auth_user.to_string(),
                    file_path)

        # keep trying to make a non-clashing file, with a sensible max attempts
        attempts = 0
        while os.path.exists(file_path):
            main_part = random_string(24)
            file_path = os.path.join(self.directory,
                                     prefix + main_part + suffix)
            attempts += 1
            if attempts > 25:  # really? Really?
                raise SynapseError(500, "Unable to create file.")

        defer.returnValue(file_path)

    def render_GET(self, request):
        # no auth here on purpose, to allow anyone to view, even across home
        # servers.

        # TODO: A little crude here, we could do this better.
        filename = request.path.split(self.directory + "/")[1]
        # be paranoid
        filename = re.sub("[^0-9A-z.-_]", "", filename)

        file_path = self.directory + "/" + filename
        if os.path.isfile(file_path):
            # filename has the content type
            base64_contentype = filename.split(".")[1]
            content_type = base64.urlsafe_b64decode(base64_contentype)
            logger.info("Sending file %s", file_path)
            f = open(file_path, 'rb')
            request.setHeader('Content-Type', content_type)
            d = FileSender().beginFileTransfer(f, request)
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

    @defer.inlineCallbacks
    def _async_render(self, request):
        try:
            fname = yield self.map_request_to_name(request)

            # TODO I have a suspcious feeling this is just going to block
            with open(fname, "wb") as f:
                f.write(request.content.read())

            respond_with_json_bytes(request, 200,
                                    json.dumps({"content_token": fname}),
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


def respond_with_json_bytes(request, code, json_bytes, send_cors=False):
    """Sends encoded JSON in response to the given request.

    Args:
        request (twisted.web.http.Request): The http request to respond to.
        code (int): The HTTP response code.
        json_bytes (bytes): The json bytes to use as the response body.
        send_cors (bool): Whether to send Cross-Origin Resource Sharing headers
            http://www.w3.org/TR/cors/
    Returns:
        twisted.web.server.NOT_DONE_YET"""

    request.setResponseCode(code)
    request.setHeader(b"Content-Type", b"application/json")

    if send_cors:
        request.setHeader("Access-Control-Allow-Origin", "*")
        request.setHeader("Access-Control-Allow-Methods",
                          "GET, POST, PUT, DELETE, OPTIONS")
        request.setHeader("Access-Control-Allow-Headers",
                          "Origin, X-Requested-With, Content-Type, Accept")

    request.write(json_bytes)
    request.finish()
    return NOT_DONE_YET
