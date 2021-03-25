# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

"""
Utility function to create an ACME issuing service.

This file contains the unconditional imports on the acme and cryptography bits that we
only need (and may only have available) if we are doing ACME, so is designed to be
imported conditionally.
"""
import logging
from typing import Dict, Iterable, List

import attr
import pem
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from josepy import JWKRSA
from josepy.jwa import RS256
from txacme.challenges import HTTP01Responder
from txacme.client import Client
from txacme.interfaces import ICertificateStore
from txacme.service import AcmeIssuingService
from txacme.util import generate_private_key
from zope.interface import implementer

from twisted.internet import defer
from twisted.internet.interfaces import IReactorTCP
from twisted.python.filepath import FilePath
from twisted.python.url import URL
from twisted.web.resource import IResource

logger = logging.getLogger(__name__)


def create_issuing_service(
    reactor: IReactorTCP,
    acme_url: str,
    account_key_file: str,
    well_known_resource: IResource,
) -> AcmeIssuingService:
    """Create an ACME issuing service, and attach it to a web Resource

    Args:
        reactor: twisted reactor
        acme_url: URL to use to request certificates
        account_key_file: where to store the account key
        well_known_resource: web resource for .well-known.
            we will attach a child resource for "acme-challenge".

    Returns:
        AcmeIssuingService
    """
    responder = HTTP01Responder()

    well_known_resource.putChild(b"acme-challenge", responder.resource)

    store = ErsatzStore()

    return AcmeIssuingService(
        cert_store=store,
        client_creator=(
            lambda: Client.from_url(
                reactor=reactor,
                url=URL.from_text(acme_url),
                key=load_or_create_client_key(account_key_file),
                alg=RS256,
            )
        ),
        clock=reactor,
        responders=[responder],
    )


@attr.s(slots=True)
@implementer(ICertificateStore)
class ErsatzStore:
    """
    A store that only stores in memory.
    """

    certs = attr.ib(type=Dict[bytes, List[bytes]], default=attr.Factory(dict))

    def store(
        self, server_name: bytes, pem_objects: Iterable[pem.AbstractPEMObject]
    ) -> defer.Deferred:
        self.certs[server_name] = [o.as_bytes() for o in pem_objects]
        return defer.succeed(None)


def load_or_create_client_key(key_file: str) -> JWKRSA:
    """Load the ACME account key from a file, creating it if it does not exist.

    Args:
        key_file: name of the file to use as the account key
    """
    # this is based on txacme.endpoint.load_or_create_client_key, but doesn't
    # hardcode the 'client.key' filename
    acme_key_file = FilePath(key_file)
    if acme_key_file.exists():
        logger.info("Loading ACME account key from '%s'", acme_key_file)
        key = serialization.load_pem_private_key(
            acme_key_file.getContent(), password=None, backend=default_backend()
        )
    else:
        logger.info("Saving new ACME account key to '%s'", acme_key_file)
        key = generate_private_key("rsa")
        acme_key_file.setContent(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return JWKRSA(key=key)
