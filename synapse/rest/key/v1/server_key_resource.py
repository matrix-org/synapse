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


import logging

from canonicaljson import encode_canonical_json
from signedjson.sign import sign_json
from unpaddedbase64 import encode_base64

from OpenSSL import crypto
from twisted.web.resource import Resource

from synapse.http.server import respond_with_json_bytes

logger = logging.getLogger(__name__)


class LocalKey(Resource):
    """HTTP resource containing encoding the TLS X.509 certificate and NACL
    signature verification keys for this server::

        GET /key HTTP/1.1

        HTTP/1.1 200 OK
        Content-Type: application/json
        {
            "server_name": "this.server.example.com"
            "verify_keys": {
                "algorithm:version": # base64 encoded NACL verification key.
            },
            "tls_certificate": # base64 ASN.1 DER encoded X.509 tls cert.
            "signatures": {
                "this.server.example.com": {
                   "algorithm:version": # NACL signature for this server.
                }
            }
        }
    """

    def __init__(self, hs):
        self.response_body = encode_canonical_json(
            self.response_json_object(hs.config)
        )
        Resource.__init__(self)

    @staticmethod
    def response_json_object(server_config):
        verify_keys = {}
        for key in server_config.signing_key:
            verify_key_bytes = key.verify_key.encode()
            key_id = "%s:%s" % (key.alg, key.version)
            verify_keys[key_id] = encode_base64(verify_key_bytes)

        x509_certificate_bytes = crypto.dump_certificate(
            crypto.FILETYPE_ASN1,
            server_config.tls_certificate
        )
        json_object = {
            u"server_name": server_config.server_name,
            u"verify_keys": verify_keys,
            u"tls_certificate": encode_base64(x509_certificate_bytes)
        }
        for key in server_config.signing_key:
            json_object = sign_json(
                json_object,
                server_config.server_name,
                key,
            )

        return json_object

    def render_GET(self, request):
        return respond_with_json_bytes(
            request, 200, self.response_body,
        )

    def getChild(self, name, request):
        if name == b'':
            return self
