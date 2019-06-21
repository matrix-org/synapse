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

import attr
from josepy.jwa import RS256
from txacme.challenges import HTTP01Responder
from txacme.client import Client
from txacme.endpoint import load_or_create_client_key
from txacme.interfaces import ICertificateStore
from txacme.service import AcmeIssuingService
from zope.interface import implementer

from twisted.internet import defer
from twisted.python.filepath import FilePath
from twisted.python.url import URL


def create_issuing_service(reactor, acme_url, pem_path, well_known_resource):
    """Create an ACME issuing service, and attach it to a web Resource

    Args:
        reactor: twisted reactor
        acme_url (str): URL to use to request certificates
        pem_path (str): where to store the client key
        well_known_resource (twisted.web.IResource): web resource for .well-known.
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
                key=load_or_create_client_key(FilePath(pem_path)),
                alg=RS256,
            )
        ),
        clock=reactor,
        responders=[responder],
    )


@attr.s
@implementer(ICertificateStore)
class ErsatzStore(object):
    """
    A store that only stores in memory.
    """

    certs = attr.ib(default=attr.Factory(dict))

    def store(self, server_name, pem_objects):
        self.certs[server_name] = [o.as_bytes() for o in pem_objects]
        return defer.succeed(None)
