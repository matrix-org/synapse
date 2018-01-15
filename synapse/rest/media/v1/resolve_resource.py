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

import re
import logging

from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer
from twisted.web.resource import Resource

import requests

from synapse.http.server import respond_with_json, request_handler
from synapse.api.errors import (
    SynapseError, Codes,
)
from synapse.http.servlet import parse_json_object_from_request
from synapse.rest.media.v1._base import validate_url_blacklist


logger = logging.getLogger(__name__)


class ResolveResource(Resource):
    isLeaf = True

    def __init__(self, hs, media_repo):
        Resource.__init__(self)

        self.media_repo = media_repo
        self.filepaths = media_repo.filepaths
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.max_upload_size = hs.config.max_upload_size
        self.url_blacklist = hs.config.url_blacklist
        self.server_name = hs.hostname
        self.auth = hs.get_auth()
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

        body = parse_json_object_from_request(request)
        url = body.get("url")

        self._validate_resource(url)

        response = requests.get(url, allow_redirects=True, stream=True)
        upload_name = self._get_filename(response)

        content_length = response.headers.get('Content-Length')
        media_type = response.headers.get("Content-Type")

        content_uri = yield self.media_repo.create_content(
            media_type, upload_name, response.raw,
            content_length, requester.user
        )

        logger.info("Uploaded content with URI %r", content_uri)

        respond_with_json(
            request, 200, {"content_uri": content_uri}, send_cors=True
        )

    def _get_filename(self, response):
        """
        Get filename from content-disposition
        """
        header = response.headers.get('content-disposition')
        if not header:
            return None
        fname = re.findall('filename=(.+)', header)
        if fname:
            return None
        return fname[0]

    def _validate_resource(self, url):
        head_response = requests.head(url, allow_redirects=True)
        self._should_have_url(url)
        self._should_be_downloadable(url, head_response)
        self._should_have_allowed_max_upload_size(url, head_response)
        self._should_have_allowed_urls(url)
        return True

    def _should_have_url(self, url):
        if not url:
            raise SynapseError(
                msg="Missing url parameter that should be passed as body of request",
                code=404,
            )

    def _should_have_allowed_urls(self, url):
        if not validate_url_blacklist(self.url_blacklist, url):
            raise SynapseError(
                403, "URL blocked by url pattern blacklist entry",
                Codes.UNKNOWN
            )

    def _should_be_downloadable(self, url, head_response):
        if head_response.status_code is not requests.codes.ok:
            raise SynapseError(
                msg="Not found resource to resolve %r" % (url),
                code=404,
            )

    def _should_have_allowed_max_upload_size(self, url, head_response):
        content_length = head_response.headers.get("Content-Length")
        if content_length is None:
            raise SynapseError(
                msg="Request must specify a Content-Length for %r" % (url),
                code=400
            )

        if int(content_length) > self.max_upload_size:
            raise SynapseError(
                msg="Upload request body is too large for %r" % (url),
                code=413,
            )

        return True
