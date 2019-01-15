# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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
from ._base import BaseHandler

import attr

from twisted.web import server, static
from twisted.internet import defer
from twisted.internet.endpoints import serverFromString
from twisted.web.resource import Resource

from zope.interface import implementer


logger = logging.getLogger(__name__)

try:
    from txacme.interfaces import ICertificateStore

    @attr.s
    @implementer(ICertificateStore)
    class ErsatzStore(object):
        """
        A store that only stores in memory.
        """

        certs = attr.ib(factory=dict)

        def store(self, server_name, pem_objects):
            self.certs[server_name] = b''.join(o.as_bytes() for o in pem_objects)
            return succeed(None)


except ImportError:
    # txacme is missing
    pass


class AcmeHandler(BaseHandler):
    def __init__(self, hs):
        super(AcmeHandler, self).__init__(hs)

        if self.hs.config.acme_enabled:
            self._setup_acme()

    def _create_key(self):
        from josepy.jwk import JWKRSA
        from txacme.util import generate_private_key

        key = generate_private_key(u'rsa')
        return JWKRSA(key=key)

    def _setup_acme(self):
        from txacme.challenges import HTTP01Responder
        from txacme.service import AcmeIssuingService
        from txacme.client import Client
        from josepy.jwa import RS256

        self._store = ErsatzStore()
        responder = HTTP01Responder()

        self._issuer = AcmeIssuingService(
            cert_store=ErsatzStore(),
            client_creator=(
                lambda: Client.from_url(
                    reactor=self.reactor,
                    url=self.config.acme_url,
                    key=self._create_key(),
                    alg=RS256,
                )
            ),
            clock=self.reactor,
            responders=[responder],
        )

        well_known = Resource()
        well_known.putChild(b'acme-challenge', responder)
        responder_resource = Resource()
        responder_resource.putChild(b'.well-known', well_known)
        responder_resource.putChild(b'check', static.Data(b'OK', b'text/plain'))

        srv = server.Site(responder_resource)

        for host in self.hs.config.acme_host.split(","):
            endpoint = serverFromString(
                self.reactor, "tcp:%s:interface=%s" % (self.hs.config.acme_port, host)
            )
            endpoint.listen(srv)

    @defer.inlineCallbacks
    def provision_certificate(self, hostname):

        yield self._issuer.issue_cert(hostname)
        defer.returnValue(self._store.certs[hostname])
