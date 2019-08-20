# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import attr
import h11
import hyperlink

from twisted.internet._resolver import FirstOneWins
from twisted.internet.defer import Deferred, ensureDeferred
from twisted.python.failure import Failure
from twisted.web.client import ResponseDone
from twisted.web.http_headers import Headers
from twisted.web.iweb import UNKNOWN_LENGTH

from .connection_pool import ConnectionPool
from .objects import Protocols, RemoteAddress


@attr.s(slots=True)
class BodyProducer:
    producer = attr.ib()
    _data = attr.ib()

    def resumeProducing(self):

        for body_data in self._data:
            self.producer.dataReceived(body_data.data)

        self.producer.connectionLost(Failure(ResponseDone()))

    def pauseProducing(self):
        pass


@attr.s(slots=True)
class HTTPRequest:

    host = attr.ib(type=bytes)
    protocol = attr.ib()
    method = attr.ib(type=bytes)
    uri = attr.ib(type=bytes)
    headers = attr.ib()
    body = attr.ib()


@attr.s(slots=True)
class _HTTPResponse:

    version = attr.ib()
    code = attr.ib()
    phrase = attr.ib()
    headers = attr.ib(repr=False)
    length = attr.ib()
    _body = attr.ib(repr=False)
    request = attr.ib(default=None)
    previousResponse = attr.ib(default=None)

    def deliverBody(self, protocol):
        producer = BodyProducer(protocol, self._body)
        producer.resumeProducing()

    def setPreviousResponse(self, response):
        self.previousResponse = response


@attr.s
class BodyConsumer:

    producer = attr.ib()
    _sender = attr.ib(default=attr.Factory(Deferred))
    _started = attr.ib(default=False)

    def start(self):
        self._started = True
        d = self.producer.startProducing(self)

        @d.addBoth
        def _(ign):
            self._sender.callback(None)

    def write(self, content):
        sender = self._sender
        self._sender = Deferred()
        sender.callback(content)

    def next_content(self):
        if not self._started:
            self.start()
        return self._sender


@attr.s(slots=True)
class H11Protocol:

    connection = attr.ib()
    _done = attr.ib(default=attr.Factory(Deferred))
    _parser = attr.ib(default=None)
    _response = attr.ib(default=attr.Factory(list), repr=False)
    _finished = attr.ib(default=True)

    @property
    def done(self):
        return self._done

    def __attrs_post_init__(self):
        self.connection.set_client(self)
        self._parser = h11.Connection(our_role=h11.CLIENT)

    async def send_request(self, request):

        header_list = []
        for key, val in request.headers.getAllRawHeaders():
            for v in val:
                header_list.append((key, v))
        header_list.extend(
            [
                (b"Host", request.host),
                (b"Connection", b"keep-alive"),
                (b"User-Agent", h11.PRODUCT_ID),
            ]
        )

        if request.body:
            if request.body.length is UNKNOWN_LENGTH:
                header_list.append((b"Transfer-Encoding", b"chunked"))
            else:
                header_list.append(
                    (b"content-length", str(request.body.length).encode("ascii"))
                )

        req = h11.Request(
            method=request.method,
            target=request.uri,
            headers=header_list,
            http_version=b"1.1",
        )
        self._send(req)

        if request.body:
            consumer = BodyConsumer(request.body)

            content = await consumer.next_content()
            while content:
                body = h11.Data(data=content)
                self._send(body)
                content = await consumer.next_content()

        end = h11.EndOfMessage()
        self._send(end)

    def _send(self, part):
        resp = self._parser.send(part)
        self.connection.write(resp)

    def _check(self):

        event = self._parser.next_event()

        while event is not h11.NEED_DATA:

            if event is h11.PAUSED:
                self._done.errback(Failure(Exception("????")))
                return

            else:
                self._response.append(event)
                if isinstance(event, h11.EndOfMessage):
                    self._finish()

            event = self._parser.next_event()

    def _finish(self):
        self._finished = True
        self.connection.reset_client()

        response = list(
            filter(lambda x: isinstance(x, h11.Response), self._response)
        ).pop()
        data = list(filter(lambda x: isinstance(x, h11.Data), self._response))

        # Convert the HTTP version
        http_version = (b"HTTP", *list(map(int, response.http_version.split(b"."))))

        # Convert the headers
        headers = Headers()
        for key, val in response.headers:
            headers.addRawHeader(key, val)

        # Try and get the length
        length = headers.getRawHeaders(b"content-length")
        if length:
            length = int(length[0])
        else:
            length = UNKNOWN_LENGTH

        returned = _HTTPResponse(
            version=http_version,
            code=response.status_code,
            phrase=response.reason,
            headers=headers,
            length=length,
            body=data,
        )

        self._done.callback(returned)

    def data_received(self, data: str) -> None:
        self._parser.receive_data(data)
        self._check()

    def connection_lost(self, reason) -> None:
        # We need to care about it here...
        self._parser.receive_data()
        self._check()


@attr.s(slots=True)
class HTTP11Client:

    reactor = attr.ib()
    pool = attr.ib(type=ConnectionPool)

    async def send_request(
        self, address: RemoteAddress, request: HTTPRequest
    ) -> _HTTPResponse:

        connection = await self.pool.request_connection(address)

        protocol = H11Protocol(connection)
        await protocol.send_request(request)

        done = await protocol.done

        connection.relinquish()

        return done

    async def _request(self, method, uri, headers=None, bodyProducer=None):

        url = hyperlink.URL.from_text(uri.decode("ascii")).to_uri()
        uri_path = url.replace(scheme=None, host=None, port=None).to_text() or "/"
        protocol = Protocols.from_scheme(url.scheme)

        # Resolve the name to an IP address
        resolved = Deferred()
        resolver_collection = FirstOneWins(resolved)
        self.reactor.nameResolver.resolveHostName(resolver_collection, url.host)
        address = await resolved

        address = RemoteAddress(
            name=url.host, addresses=[address], port=url.port, protocol=protocol
        )

        req = HTTPRequest(
            host=url.host.encode("ascii"),
            protocol=protocol,
            method=method,
            uri=uri_path.encode("ascii"),
            headers=headers,
            body=bodyProducer,
        )

        resp = await self.send_request(address, req)

        return resp

    def request(self, method, uri, headers=None, bodyProducer=None):
        return ensureDeferred(
            self._request(method, uri, headers=headers, bodyProducer=bodyProducer)
        )


if __name__ == "__main__":

    from treq.client import HTTPClient

    from twisted.internet.task import react
    from twisted.web.client import BrowserLikePolicyForHTTPS

    async def run(reactor):

        copts = BrowserLikePolicyForHTTPS()

        pool = ConnectionPool(reactor=reactor, tls_factory=copts)
        agent = HTTP11Client(reactor, pool)

        client = HTTPClient(agent)

        res = await client.get("https://google.com")

        print(res)
        print(res.headers)
        print("?")

        print(await res.content())

    react(lambda reactor: ensureDeferred(run(reactor)))
