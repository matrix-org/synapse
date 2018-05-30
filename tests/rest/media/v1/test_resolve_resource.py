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
import json
import contextlib
import random

from mock import Mock

from tests import unittest
from tests.utils import MockMediaRepo, setup_test_homeserver

from twisted.internet import defer
from twisted.internet.defer import succeed
from twisted.web import server
from twisted.web.test.test_web import DummyRequest

from synapse.http.request_metrics import (
    requests_counter,
)
from synapse.api.auth import Auth
from synapse.rest.media.v1.resolve_resource import ResolveResource


class SmartDummyRequest(DummyRequest):
    def __init__(self, method, url, args=None, headers=None):
        DummyRequest.__init__(self, url.split('/'))
        self.method = method
        self.request_seq = random.randint(0, 100)
        self.request_metrics = requests_counter

        args = args or {}
        for k, v in args.items():
            self.addArg(k, v)

        headers = headers or {}
        for k, v in headers.items():
            self.requestHeaders.addRawHeader(k, v)

    @property
    def resp_body(self):
        return "".join(self.written)

    @property
    def resp_json_body(self):
        return json.loads(self.resp_body)

    @contextlib.contextmanager
    def processing(self):
        yield

    def get_request_id(self):
        return "%s-%i" % (self.method, self.request_seq)


class DummySite(server.Site):
    def get(self, url, args=None, headers=None):
        return self._request("GET", url, args, headers)

    def post(self, url, args=None, headers=None):
        return self._request("POST", url, args, headers)

    def _request(self, method, url, args, headers):
        request = SmartDummyRequest(method, url, args, headers)
        resource = self.getResourceFor(request)
        result = resource.render(request)
        return self._resolveResult(request, result)

    def _resolveResult(self, request, result):
        if isinstance(result, str):
            request.write(result)
            request.finish()
            return succeed(request)
        elif result is server.NOT_DONE_YET:
            if request.finished:
                return succeed(request)
            else:
                return request.notifyFinish().addCallback(lambda _: request)
        else:
            raise ValueError("Unexpected return value: %r" % (result,))


_PATH_PREFIX = "/"
_EXAMPLE_IMAGE_URL = "https://upload.wikimedia.org/wikipedia/commons/thumb/" \
    "f/f8/Python_logo_and_wordmark.svg/486px-Python_logo_and_wordmark.svg.png"
_TEST_USER = "@foo:bar"
_TEST_TOKEN = "_test_token_"
_TEST_USER_INFO = {
    "name": _TEST_USER,
    "token_id": "ditto",
    "device_id": "device",
}


class ResolveResourceTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.store = Mock()

        self.hs = yield setup_test_homeserver()
        self.hs.get_datastore = Mock(return_value=self.store)

        self.auth = Auth(self.hs)
        self.hs.get_auth = Mock(return_value=self.auth)
        self.hs.config.max_upload_size = 20000

        self.media_repo = MockMediaRepo()
        resource = ResolveResource(self.hs, self.media_repo)
        self.web = DummySite(resource)

    @property
    def _resolve_url(self):
        return '{}/resolve_url'.format(_PATH_PREFIX)

    @property
    def _headers(self):
        return {}

    def _get_args(self, token=_TEST_TOKEN):
        # TODO: replace args by body url: url request for using json there.
        return dict(
            body=json.dumps(dict(url=_EXAMPLE_IMAGE_URL)),
            access_token=_TEST_TOKEN)

    @defer.inlineCallbacks
    def test_authentication_requirements_before_processing_resolve_request(self):
        request = yield self.web.post(self._resolve_url, self._get_args())
        self.assertEqual(request.responseCode, 500)

    @defer.inlineCallbacks
    def test_resource_resource(self):
        content_uri = 'mxc://test.host/12345'

        app_service = Mock(token=_TEST_TOKEN, sender=_TEST_USER)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = Mock(return_value=_TEST_USER_INFO)
        # should create the new resource from the downloaded resource.
        self.media_repo.create_content = Mock(return_value=content_uri)

        request = yield self.web.post(
            '{}/resolve_url'.format(_PATH_PREFIX),
            self._get_args(), self._headers)
        self.assertEqual(request.responseCode, 200)

        resp = request.resp_json_body
        '''we should respond with url to downloadable
        and previewable resource'''
        self.assertTrue('content_uri' in resp)
        self.assertTrue('msgtype' in resp)
        self.assertTrue(resp['content_uri'] == content_uri)
        self.assertTrue(resp['msgtype'] == "m.image")
