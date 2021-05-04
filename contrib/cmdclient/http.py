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
import urllib
from pprint import pformat
from typing import Optional

from twisted.internet import defer, reactor
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers


class HttpClient:
    """Interface for talking json over http"""

    def put_json(self, url, data):
        """Sends the specifed json data using PUT

        Args:
            url (str): The URL to PUT data to.
            data (dict): A dict containing the data that will be used as
                the request body. This will be encoded as JSON.

        Returns:
            Deferred: Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body.
        """
        pass

    def get_json(self, url, args=None):
        """Gets some json from the given host homeserver and path

        Args:
            url (str): The URL to GET data from.
            args (dict): A dictionary used to create query strings, defaults to
                None.
                **Note**: The value of each key is assumed to be an iterable
                and *not* a string.

        Returns:
            Deferred: Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body.
        """
        pass


class TwistedHttpClient(HttpClient):
    """Wrapper around the twisted HTTP client api.

    Attributes:
        agent (twisted.web.client.Agent): The twisted Agent used to send the
            requests.
    """

    def __init__(self):
        self.agent = Agent(reactor)

    @defer.inlineCallbacks
    def put_json(self, url, data):
        response = yield self._create_put_request(
            url, data, headers_dict={"Content-Type": ["application/json"]}
        )
        body = yield readBody(response)
        defer.returnValue((response.code, body))

    @defer.inlineCallbacks
    def get_json(self, url, args=None):
        if args:
            # generates a list of strings of form "k=v".
            qs = urllib.urlencode(args, True)
            url = "%s?%s" % (url, qs)
        response = yield self._create_get_request(url)
        body = yield readBody(response)
        defer.returnValue(json.loads(body))

    def _create_put_request(self, url, json_data, headers_dict: Optional[dict] = None):
        """Wrapper of _create_request to issue a PUT request"""
        headers_dict = headers_dict or {}

        if "Content-Type" not in headers_dict:
            raise defer.error(RuntimeError("Must include Content-Type header for PUTs"))

        return self._create_request(
            "PUT", url, producer=_JsonProducer(json_data), headers_dict=headers_dict
        )

    def _create_get_request(self, url, headers_dict: Optional[dict] = None):
        """Wrapper of _create_request to issue a GET request"""
        return self._create_request("GET", url, headers_dict=headers_dict or {})

    @defer.inlineCallbacks
    def do_request(
        self,
        method,
        url,
        data=None,
        qparams=None,
        jsonreq=True,
        headers: Optional[dict] = None,
    ):
        headers = headers or {}

        if qparams:
            url = "%s?%s" % (url, urllib.urlencode(qparams, True))

        if jsonreq:
            prod = _JsonProducer(data)
            headers["Content-Type"] = ["application/json"]
        else:
            prod = _RawProducer(data)

        if method in ["POST", "PUT"]:
            response = yield self._create_request(
                method, url, producer=prod, headers_dict=headers
            )
        else:
            response = yield self._create_request(method, url)

        body = yield readBody(response)
        defer.returnValue(json.loads(body))

    @defer.inlineCallbacks
    def _create_request(
        self, method, url, producer=None, headers_dict: Optional[dict] = None
    ):
        """Creates and sends a request to the given url"""
        headers_dict = headers_dict or {}

        headers_dict["User-Agent"] = ["Synapse Cmd Client"]

        retries_left = 5
        print("%s to %s with headers %s" % (method, url, headers_dict))
        if self.verbose and producer:
            if "password" in producer.data:
                temp = producer.data["password"]
                producer.data["password"] = "[REDACTED]"
                print(json.dumps(producer.data, indent=4))
                producer.data["password"] = temp
            else:
                print(json.dumps(producer.data, indent=4))

        while True:
            try:
                response = yield self.agent.request(
                    method, url.encode("UTF8"), Headers(headers_dict), producer
                )
                break
            except Exception as e:
                print("uh oh: %s" % e)
                if retries_left:
                    yield self.sleep(2 ** (5 - retries_left))
                    retries_left -= 1
                else:
                    raise e

        if self.verbose:
            print("Status %s %s" % (response.code, response.phrase))
            print(pformat(list(response.headers.getAllRawHeaders())))
        defer.returnValue(response)

    def sleep(self, seconds):
        d = defer.Deferred()
        reactor.callLater(seconds, d.callback, seconds)
        return d


class _RawProducer:
    def __init__(self, data):
        self.data = data
        self.body = data
        self.length = len(self.body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


class _JsonProducer:
    """Used by the twisted http client to create the HTTP body from json"""

    def __init__(self, jsn):
        self.data = jsn
        self.body = json.dumps(jsn).encode("utf8")
        self.length = len(self.body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass
