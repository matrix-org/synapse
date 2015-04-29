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
from syutil.crypto.jsonsign import (
    verify_signed_json, signature_ids, sign_json, encode_canonical_json
)
from syutil.crypto.signing_key import (
    is_signing_algorithm_supported, decode_verify_key_bytes
)
from syutil.base64util import decode_base64, encode_base64
from synapse.api.errors import SynapseError, Codes

from synapse.util.retryutils import get_retry_limiter

from synapse.util.async import create_observer

from OpenSSL import crypto

import urllib
import hashlib
import logging


logger = logging.getLogger(__name__)


class Keyring(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.client = hs.get_http_client()
        self.config = hs.get_config()
        self.perspective_servers = self.config.perspectives
        self.hs = hs

        self.key_downloads = {}

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
        except IOError as e:
            logger.warn(
                "Got IOError when downloading keys for %s: %s %s",
                server_name, type(e).__name__, str(e.message),
            )
            raise SynapseError(
                502,
                "Error downloading keys for %s" % (server_name,),
                Codes.UNAUTHORIZED,
            )
        except Exception as e:
            logger.warn(
                "Got Exception when downloading keys for %s: %s %s",
                server_name, type(e).__name__, str(e.message),
            )
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
        Trys to fetch the key from a trusted perspective server first.
        Args:
            server_name(str): The name of the server to fetch a key for.
            keys_ids (list of str): The key_ids to check for.
        """
        cached = yield self.store.get_server_verify_keys(server_name, key_ids)

        if cached:
            defer.returnValue(cached[0])
            return

        download = self.key_downloads.get(server_name)

        if download is None:
            download = self._get_server_verify_key_impl(server_name, key_ids)
            self.key_downloads[server_name] = download

            @download.addBoth
            def callback(ret):
                del self.key_downloads[server_name]
                return ret

        r = yield create_observer(download)
        defer.returnValue(r)

    @defer.inlineCallbacks
    def _get_server_verify_key_impl(self, server_name, key_ids):
        keys = None
        for perspective_name, perspective_keys in self.perspective_servers.items():
            try:
                keys = yield self.get_server_verify_key_v2_indirect(
                    server_name, key_ids, perspective_name, perspective_keys
                )
                break
            except:
                logging.info(
                    "Unable to getting key %r for %r from %r",
                    key_ids, server_name, perspective_name,
                )
                pass

        limiter = yield get_retry_limiter(
            server_name,
            self.clock,
            self.store,
        )

        with limiter:
            if keys is None:
                try:
                    keys = yield self.get_server_verify_key_v2_direct(
                        server_name, key_ids
                    )
                except:
                    pass

            keys = yield self.get_server_verify_key_v1_direct(
                server_name, key_ids
            )

        for key_id in key_ids:
            if key_id in keys:
                defer.returnValue(keys[key_id])
                return
        raise ValueError("No verification key found for given key ids")

    @defer.inlineCallbacks
    def get_server_verify_key_v2_indirect(self, server_name, key_ids,
                                          perspective_name,
                                          perspective_keys):
        limiter = yield get_retry_limiter(
            perspective_name, self.clock, self.store
        )

        with limiter:
            # TODO(mark): Set the minimum_valid_until_ts to that needed by
            # the events being validated or the current time if validating
            # an incoming request.
            responses = yield self.client.post_json(
                destination=perspective_name,
                path=b"/_matrix/key/v2/query",
                data={
                    u"server_keys": {
                        server_name: {
                            key_id: {
                                u"minimum_valid_until_ts": 0
                            } for key_id in key_ids
                        }
                    }
                },
            )

        keys = {}

        for response in responses:
            if (u"signatures" not in response
                    or perspective_name not in response[u"signatures"]):
                raise ValueError(
                    "Key response not signed by perspective server"
                    " %r" % (perspective_name,)
                )

            verified = False
            for key_id in response[u"signatures"][perspective_name]:
                if key_id in perspective_keys:
                    verify_signed_json(
                        response,
                        perspective_name,
                        perspective_keys[key_id]
                    )
                    verified = True

            if not verified:
                logging.info(
                    "Response from perspective server %r not signed with a"
                    " known key, signed with: %r, known keys: %r",
                    perspective_name,
                    list(response[u"signatures"][perspective_name]),
                    list(perspective_keys)
                )
                raise ValueError(
                    "Response not signed with a known key for perspective"
                    " server %r" % (perspective_name,)
                )

            response_keys = yield self.process_v2_response(
                server_name, perspective_name, response
            )

            keys.update(response_keys)

        yield self.store_keys(
            server_name=server_name,
            from_server=perspective_name,
            verify_keys=keys,
        )

        defer.returnValue(keys)

    @defer.inlineCallbacks
    def get_server_verify_key_v2_direct(self, server_name, key_ids):

        keys = {}

        for requested_key_id in key_ids:
            if requested_key_id in keys:
                continue

            (response, tls_certificate) = yield fetch_server_key(
                server_name, self.hs.tls_context_factory,
                path=(b"/_matrix/key/v2/server/%s" % (
                    urllib.quote(requested_key_id),
                )).encode("ascii"),
            )

            if (u"signatures" not in response
                    or server_name not in response[u"signatures"]):
                raise ValueError("Key response not signed by remote server")

            if "tls_fingerprints" not in response:
                raise ValueError("Key response missing TLS fingerprints")

            certificate_bytes = crypto.dump_certificate(
                crypto.FILETYPE_ASN1, tls_certificate
            )
            sha256_fingerprint = hashlib.sha256(certificate_bytes).digest()
            sha256_fingerprint_b64 = encode_base64(sha256_fingerprint)

            response_sha256_fingerprints = set()
            for fingerprint in response[u"tls_fingerprints"]:
                if u"sha256" in fingerprint:
                    response_sha256_fingerprints.add(fingerprint[u"sha256"])

            if sha256_fingerprint_b64 not in response_sha256_fingerprints:
                raise ValueError("TLS certificate not allowed by fingerprints")

            response_keys = yield self.process_v2_response(
                server_name=server_name,
                from_server=server_name,
                requested_id=requested_key_id,
                response_json=response,
            )

            keys.update(response_keys)

        yield self.store_keys(
            server_name=server_name,
            from_server=server_name,
            verify_keys=keys,
        )

        defer.returnValue(keys)

    @defer.inlineCallbacks
    def process_v2_response(self, server_name, from_server, response_json,
                            requested_id=None):
        time_now_ms = self.clock.time_msec()
        response_keys = {}
        verify_keys = {}
        for key_id, key_data in response_json["verify_keys"].items():
            if is_signing_algorithm_supported(key_id):
                key_base64 = key_data["key"]
                key_bytes = decode_base64(key_base64)
                verify_key = decode_verify_key_bytes(key_id, key_bytes)
                verify_key.time_added = time_now_ms
                verify_keys[key_id] = verify_key

        old_verify_keys = {}
        for key_id, key_data in response_json["old_verify_keys"].items():
            if is_signing_algorithm_supported(key_id):
                key_base64 = key_data["key"]
                key_bytes = decode_base64(key_base64)
                verify_key = decode_verify_key_bytes(key_id, key_bytes)
                verify_key.expired = key_data["expired_ts"]
                verify_key.time_added = time_now_ms
                old_verify_keys[key_id] = verify_key

        for key_id in response_json["signatures"][server_name]:
            if key_id not in response_json["verify_keys"]:
                raise ValueError(
                    "Key response must include verification keys for all"
                    " signatures"
                )
            if key_id in verify_keys:
                verify_signed_json(
                    response_json,
                    server_name,
                    verify_keys[key_id]
                )

        signed_key_json = sign_json(
            response_json,
            self.config.server_name,
            self.config.signing_key[0],
        )

        signed_key_json_bytes = encode_canonical_json(signed_key_json)
        ts_valid_until_ms = signed_key_json[u"valid_until_ts"]

        updated_key_ids = set()
        if requested_id is not None:
            updated_key_ids.add(requested_id)
        updated_key_ids.update(verify_keys)
        updated_key_ids.update(old_verify_keys)

        response_keys.update(verify_keys)
        response_keys.update(old_verify_keys)

        for key_id in updated_key_ids:
            yield self.store.store_server_keys_json(
                server_name=server_name,
                key_id=key_id,
                from_server=server_name,
                ts_now_ms=time_now_ms,
                ts_expires_ms=ts_valid_until_ms,
                key_json_bytes=signed_key_json_bytes,
            )

        defer.returnValue(response_keys)

        raise ValueError("No verification key found for given key ids")

    @defer.inlineCallbacks
    def get_server_verify_key_v1_direct(self, server_name, key_ids):
        """Finds a verification key for the server with one of the key ids.
        Args:
            server_name (str): The name of the server to fetch a key for.
            keys_ids (list of str): The key_ids to check for.
        """

        # Try to fetch the key from the remote server.

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

        # Cache the result in the datastore.

        time_now_ms = self.clock.time_msec()

        verify_keys = {}
        for key_id, key_base64 in response["verify_keys"].items():
            if is_signing_algorithm_supported(key_id):
                key_bytes = decode_base64(key_base64)
                verify_key = decode_verify_key_bytes(key_id, key_bytes)
                verify_key.time_added = time_now_ms
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

        yield self.store.store_server_certificate(
            server_name,
            server_name,
            time_now_ms,
            tls_certificate,
        )

        yield self.store_keys(
            server_name=server_name,
            from_server=server_name,
            verify_keys=verify_keys,
        )

        defer.returnValue(verify_keys)

    @defer.inlineCallbacks
    def store_keys(self, server_name, from_server, verify_keys):
        """Store a collection of verify keys for a given server
        Args:
            server_name(str): The name of the server the keys are for.
            from_server(str): The server the keys were downloaded from.
            verify_keys(dict): A mapping of key_id to VerifyKey.
        Returns:
            A deferred that completes when the keys are stored.
        """
        for key_id, key in verify_keys.items():
            # TODO(markjh): Store whether the keys have expired.
            yield self.store.store_server_verify_key(
                server_name, server_name, key.time_added, key
            )
