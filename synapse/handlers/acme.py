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

import attr
from zope.interface import implementer

from OpenSSL import crypto
from twisted.internet import defer
from twisted.internet.endpoints import serverFromString
from twisted.python.filepath import FilePath
from twisted.python.url import URL
from twisted.web import server, static
from twisted.web.resource import Resource

logger = logging.getLogger(__name__)

try:
    from txacme.interfaces import ICertificateStore

    @attr.s
    @implementer(ICertificateStore)
    class ErsatzStore(object):
        """
        A store that only stores in memory.
        """

        certs = attr.ib(default=attr.Factory(dict))

        def store(self, server_name, pem_objects):
            self.certs[server_name] = b''.join(o.as_bytes() for o in pem_objects)
            return defer.succeed(None)


except ImportError:
    # txacme is missing
    pass


class AcmeHandler(object):
    def __init__(self, hs):
        self.hs = hs
        self.reactor = hs.get_reactor()

    def start_listening(self):

        # Configure logging for txacme, if you need to debug
        # from eliot import add_destinations
        # from eliot.twisted import TwistedDestination
        #
        # add_destinations(TwistedDestination())

        from txacme.challenges import HTTP01Responder
        from txacme.service import AcmeIssuingService
        from txacme.endpoint import load_or_create_client_key
        from txacme.client import Client
        from josepy.jwa import RS256

        self._store = ErsatzStore()
        responder = HTTP01Responder()

        self._issuer = AcmeIssuingService(
            cert_store=self._store,
            client_creator=(
                lambda: Client.from_url(
                    reactor=self.reactor,
                    url=URL.from_text(self.hs.config.acme_url),
                    key=load_or_create_client_key(
                        FilePath(self.hs.config.acme_client_key)
                    ),
                    alg=RS256,
                )
            ),
            clock=self.reactor,
            responders=[responder],
        )

        well_known = Resource()
        well_known.putChild(b'acme-challenge', responder.resource)
        responder_resource = Resource()
        responder_resource.putChild(b'.well-known', well_known)
        responder_resource.putChild(b'check', static.Data(b'OK', b'text/plain'))

        srv = server.Site(responder_resource)

        listeners = []

        for host in self.hs.config.acme_bind_addresses:
            logger.info(
                "Listening for ACME requests on %s:%s", host, self.hs.config.acme_port
            )
            endpoint = serverFromString(
                self.reactor, "tcp:%s:interface=%s" % (self.hs.config.acme_port, host)
            )
            listeners.append(endpoint.listen(srv))

        # Make sure we are registered to the ACME server. There's no public API
        # for this, it is usually triggered by startService, but since we don't
        # want it to control where we save the certificates, we have to reach in
        # and trigger the registration machinery ourselves.
        yield self._issuer._ensure_registered()
        self._issuer._registered = False

        # Return a Deferred that will fire when all the servers have started up.
        return defer.DeferredList(listeners, fireOnOneErrback=True, consumeErrors=True)

    @defer.inlineCallbacks
    def provision_certificate(self):

        logger.warning("Reprovisioning %s", hs.hostname)

        try:
            yield self._issuer.issue_cert(hs.hostname)
        except Exception:
            logger.exception("Fail!")
            raise
        logger.warning("Reprovisioned %s, saving.", hs.hostname)
        cert_chain = self._store.certs[hs.hostname]

        try:
            tls_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, cert_chain)
            with open(self.hs.config.tls_private_key_file, "wb") as private_key_file:
                private_key_pem = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, tls_private_key
                )
                private_key_file.write(private_key_pem)

            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_chain)
            with open(self.hs.config.tls_certificate_file, "wb") as certificate_file:
                cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                certificate_file.write(cert_pem)
        except Exception:
            logger.exception("Failed saving!")
            raise

        defer.returnValue(True)
