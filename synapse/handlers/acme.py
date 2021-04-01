# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
from typing import TYPE_CHECKING

import twisted
import twisted.internet.error
from twisted.web import server, static
from twisted.web.resource import Resource

from synapse.app import check_bind_error

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

ACME_REGISTER_FAIL_ERROR = """
--------------------------------------------------------------------------------
Failed to register with the ACME provider. This is likely happening because the installation
is new, and ACME v1 has been deprecated by Let's Encrypt and disabled for
new installations since November 2019.
At the moment, Synapse doesn't support ACME v2. For more information and alternative
solutions, please read https://github.com/matrix-org/synapse/blob/master/docs/ACME.md#deprecation-of-acme-v1
--------------------------------------------------------------------------------"""


class AcmeHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.reactor = hs.get_reactor()
        self._acme_domain = hs.config.acme_domain

    async def start_listening(self) -> None:
        from synapse.handlers import acme_issuing_service

        # Configure logging for txacme, if you need to debug
        # from eliot import add_destinations
        # from eliot.twisted import TwistedDestination
        #
        # add_destinations(TwistedDestination())

        well_known = Resource()

        self._issuer = acme_issuing_service.create_issuing_service(
            self.reactor,
            acme_url=self.hs.config.acme_url,
            account_key_file=self.hs.config.acme_account_key_file,
            well_known_resource=well_known,
        )

        responder_resource = Resource()
        responder_resource.putChild(b".well-known", well_known)
        responder_resource.putChild(b"check", static.Data(b"OK", b"text/plain"))
        srv = server.Site(responder_resource)

        bind_addresses = self.hs.config.acme_bind_addresses
        for host in bind_addresses:
            logger.info(
                "Listening for ACME requests on %s:%i", host, self.hs.config.acme_port
            )
            try:
                self.reactor.listenTCP(
                    self.hs.config.acme_port, srv, backlog=50, interface=host
                )
            except twisted.internet.error.CannotListenError as e:
                check_bind_error(e, host, bind_addresses)

        # Make sure we are registered to the ACME server. There's no public API
        # for this, it is usually triggered by startService, but since we don't
        # want it to control where we save the certificates, we have to reach in
        # and trigger the registration machinery ourselves.
        self._issuer._registered = False

        try:
            await self._issuer._ensure_registered()
        except Exception:
            logger.error(ACME_REGISTER_FAIL_ERROR)
            raise

    async def provision_certificate(self) -> None:

        logger.warning("Reprovisioning %s", self._acme_domain)

        try:
            await self._issuer.issue_cert(self._acme_domain)
        except Exception:
            logger.exception("Fail!")
            raise
        logger.warning("Reprovisioned %s, saving.", self._acme_domain)
        cert_chain = self._issuer.cert_store.certs[self._acme_domain]

        try:
            with open(self.hs.config.tls_private_key_file, "wb") as private_key_file:
                for x in cert_chain:
                    if x.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
                        private_key_file.write(x)

            with open(self.hs.config.tls_certificate_file, "wb") as certificate_file:
                for x in cert_chain:
                    if x.startswith(b"-----BEGIN CERTIFICATE-----"):
                        certificate_file.write(x)
        except Exception:
            logger.exception("Failed saving!")
            raise
