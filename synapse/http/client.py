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

from synapse.api.errors import CodeMessageException
from syutil.jsonutil import encode_canonical_json

from twisted.internet import defer, reactor
from twisted.web.client import (
    Agent, readBody, FileBodyProducer, PartialDownloadError
)
from twisted.web.http_headers import Headers

from StringIO import StringIO

import simplejson as json
import logging
import urllib


logger = logging.getLogger(__name__)


class SimpleHttpClient(object):
    """
    A simple, no-frills HTTP client with methods that wrap up common ways of
    using HTTP in Matrix
    """
    def __init__(self, hs):
        self.hs = hs
        # The default context factory in Twisted 14.0.0 (which we require) is
        # BrowserLikePolicyForHTTPS which will do regular cert validation
        # 'like a browser'
        self.agent = Agent(reactor)
        self.version_string = hs.version_string

    @defer.inlineCallbacks
    def post_urlencoded_get_json(self, uri, args={}):
        logger.debug("post_urlencoded_get_json args: %s", args)
        query_bytes = urllib.urlencode(args, True)

        response = yield self.agent.request(
            "POST",
            uri.encode("ascii"),
            headers=Headers({
                b"Content-Type": [b"application/x-www-form-urlencoded"],
                b"User-Agent": [self.version_string],
            }),
            bodyProducer=FileBodyProducer(StringIO(query_bytes))
        )

        body = yield readBody(response)

        defer.returnValue(json.loads(body))

    @defer.inlineCallbacks
    def post_json_get_json(self, uri, post_json):
        json_str = encode_canonical_json(post_json)

        logger.info("HTTP POST %s -> %s", json_str, uri)

        response = yield self.agent.request(
            "POST",
            uri.encode("ascii"),
            headers=Headers({
                "Content-Type": ["application/json"]
            }),
            bodyProducer=FileBodyProducer(StringIO(json_str))
        )

        body = yield readBody(response)

        defer.returnValue(json.loads(body))

    @defer.inlineCallbacks
    def get_json(self, uri, args={}):
        """ Gets some json from the given URI.

        Args:
            uri (str): The URI to request, not including query parameters
            args (dict): A dictionary used to create query strings, defaults to
                None.
                **Note**: The value of each key is assumed to be an iterable
                and *not* a string.
        Returns:
            Deferred: Succeeds when we get *any* 2xx HTTP response, with the
            HTTP body as JSON.
        Raises:
            On a non-2xx HTTP response. The response body will be used as the
            error message.
        """
        if len(args):
            query_bytes = urllib.urlencode(args, True)
            uri = "%s?%s" % (uri, query_bytes)

        response = yield self.agent.request(
            "GET",
            uri.encode("ascii"),
            headers=Headers({
                b"User-Agent": [self.version_string],
            })
        )

        body = yield readBody(response)

        if 200 <= response.code < 300:
            defer.returnValue(json.loads(body))
        else:
            # NB: This is explicitly not json.loads(body)'d because the contract
            # of CodeMessageException is a *string* message. Callers can always
            # load it into JSON if they want.
            raise CodeMessageException(response.code, body)

    @defer.inlineCallbacks
    def put_json(self, uri, json_body, args={}):
        """ Puts some json to the given URI.

        Args:
            uri (str): The URI to request, not including query parameters
            json_body (dict): The JSON to put in the HTTP body,
            args (dict): A dictionary used to create query strings, defaults to
                None.
                **Note**: The value of each key is assumed to be an iterable
                and *not* a string.
        Returns:
            Deferred: Succeeds when we get *any* 2xx HTTP response, with the
            HTTP body as JSON.
        Raises:
            On a non-2xx HTTP response.
        """
        if len(args):
            query_bytes = urllib.urlencode(args, True)
            uri = "%s?%s" % (uri, query_bytes)

        json_str = json.dumps(json_body)

        response = yield self.agent.request(
            "PUT",
            uri.encode("ascii"),
            headers=Headers({
                b"User-Agent": [self.version_string],
                "Content-Type": ["application/json"]
            }),
            bodyProducer=FileBodyProducer(StringIO(json_str))
        )

        body = yield readBody(response)

        if 200 <= response.code < 300:
            defer.returnValue(json.loads(body))
        else:
            # NB: This is explicitly not json.loads(body)'d because the contract
            # of CodeMessageException is a *string* message. Callers can always
            # load it into JSON if they want.
            raise CodeMessageException(response.code, body)


class CaptchaServerHttpClient(SimpleHttpClient):
    """
    Separate HTTP client for talking to google's captcha servers
    Only slightly special because accepts partial download responses
    """

    @defer.inlineCallbacks
    def post_urlencoded_get_raw(self, url, args={}):
        query_bytes = urllib.urlencode(args, True)

        response = yield self.agent.request(
            "POST",
            url.encode("ascii"),
            bodyProducer=FileBodyProducer(StringIO(query_bytes)),
            headers=Headers({
                b"Content-Type": [b"application/x-www-form-urlencoded"],
                b"User-Agent": [self.version_string],
            })
        )

        try:
            body = yield readBody(response)
            defer.returnValue(body)
        except PartialDownloadError as e:
            # twisted dislikes google's response, no content length.
            defer.returnValue(e.response)


def _print_ex(e):
    if hasattr(e, "reasons") and e.reasons:
        for ex in e.reasons:
            _print_ex(ex)
    else:
        logger.exception(e)
