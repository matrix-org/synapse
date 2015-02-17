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

from synapse.crypto.keyclient import fetch_server_key
from twisted.internet import defer
from syutil.crypto.jsonsign import verify_signed_json, signature_ids
from syutil.crypto.signing_key import (
    is_signing_algorithm_supported, decode_verify_key_bytes
)
from syutil.base64util import decode_base64, encode_base64
from synapse.api.errors import SynapseError, Codes

from synapse.util.retryutils import get_retry_limiter

from OpenSSL import crypto

import logging


logger = logging.getLogger(__name__)


class Keyring(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.hs = hs

    @defer.inlineCallbacks
    def verify_json_for_server(self, server_name, json_object):
        logger.debug("Verifying for %s", server_name)
        key_ids = signature_ids(json_object, server_name)
        if not key_ids:
            raise SynapseError(
                400,
                "Not signed with a supported algorithm",
                Codes.UNAUTHORIZED,
            )
        try:
            verify_key = yield self.get_server_verify_key(server_name, key_ids)
        except IOError:
            raise SynapseError(
                502,
                "Error downloading keys for %s" % (server_name,),
                Codes.UNAUTHORIZED,
            )
        except:
            raise SynapseError(
                401,
                "No key for %s with id %s" % (server_name, key_ids),
                Codes.UNAUTHORIZED,
            )
        try:
            verify_signed_json(json_object, server_name, verify_key)
        except:
            raise SynapseError(
                401,
                "Invalid signature for server %s with key %s:%s" % (
                    server_name, verify_key.alg, verify_key.version
                ),
                Codes.UNAUTHORIZED,
            )

    @defer.inlineCallbacks
    def get_server_verify_key(self, server_name, key_ids):
        """Finds a verification key for the server with one of the key ids.
        Args:
            server_name (str): The name of the server to fetch a key for.
            keys_ids (list of str): The key_ids to check for.
        """

        # Check the datastore to see if we have one cached.
        cached = yield self.store.get_server_verify_keys(server_name, key_ids)

        if cached:
            defer.returnValue(cached[0])
            return

        # Try to fetch the key from the remote server.

        limiter = yield get_retry_limiter(
            server_name,
            self.clock,
            self.store,
        )

        with limiter:
            (response, tls_certificate) = yield fetch_server_key(
                server_name, self.hs.tls_context_factory
            )

        # Check the response.

        x509_certificate_bytes = crypto.dump_certificate(
            crypto.FILETYPE_ASN1, tls_certificate
        )

        if ("signatures" not in response
                or server_name not in response["signatures"]):
            raise ValueError("Key response not signed by remote server")

        if "tls_certificate" not in response:
            raise ValueError("Key response missing TLS certificate")

        tls_certificate_b64 = response["tls_certificate"]

        if encode_base64(x509_certificate_bytes) != tls_certificate_b64:
            raise ValueError("TLS certificate doesn't match")

        verify_keys = {}
        for key_id, key_base64 in response["verify_keys"].items():
            if is_signing_algorithm_supported(key_id):
                key_bytes = decode_base64(key_base64)
                verify_key = decode_verify_key_bytes(key_id, key_bytes)
                verify_keys[key_id] = verify_key

        for key_id in response["signatures"][server_name]:
            if key_id not in response["verify_keys"]:
                raise ValueError(
                    "Key response must include verification keys for all"
                    " signatures"
                )
            if key_id in verify_keys:
                verify_signed_json(
                    response,
                    server_name,
                    verify_keys[key_id]
                )

        # Cache the result in the datastore.

        time_now_ms = self.clock.time_msec()

        yield self.store.store_server_certificate(
            server_name,
            server_name,
            time_now_ms,
            tls_certificate,
        )

        for key_id, key in verify_keys.items():
            yield self.store.store_server_verify_key(
                server_name, server_name, time_now_ms, key
            )

        for key_id in key_ids:
            if key_id in verify_keys:
                defer.returnValue(verify_keys[key_id])
                return

        raise ValueError("No verification key found for given key ids")
