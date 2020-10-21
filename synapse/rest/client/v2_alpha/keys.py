# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.api.errors import SynapseError
from synapse.http.servlet import (
    RestServlet,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
)
from synapse.logging.opentracing import log_kv, set_tag, trace
from synapse.types import StreamToken

from ._base import client_patterns, interactive_auth_handler

logger = logging.getLogger(__name__)


class KeyUploadServlet(RestServlet):
    """
    POST /keys/upload HTTP/1.1
    Content-Type: application/json

    {
      "device_keys": {
        "user_id": "<user_id>",
        "device_id": "<device_id>",
        "valid_until_ts": <millisecond_timestamp>,
        "algorithms": [
          "m.olm.curve25519-aes-sha2",
        ]
        "keys": {
          "<algorithm>:<device_id>": "<key_base64>",
        },
        "signatures:" {
          "<user_id>" {
            "<algorithm>:<device_id>": "<signature_base64>"
      } } },
      "one_time_keys": {
        "<algorithm>:<key_id>": "<key_base64>"
      },
    }
    """

    PATTERNS = client_patterns("/keys/upload(/(?P<device_id>[^/]+))?$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super().__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()

    @trace(opname="upload_keys")
    async def on_POST(self, request, device_id):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        if device_id is not None:
            # passing the device_id here is deprecated; however, we allow it
            # for now for compatibility with older clients.
            if requester.device_id is not None and device_id != requester.device_id:
                set_tag("error", True)
                log_kv(
                    {
                        "message": "Client uploading keys for a different device",
                        "logged_in_id": requester.device_id,
                        "key_being_uploaded": device_id,
                    }
                )
                logger.warning(
                    "Client uploading keys for a different device "
                    "(logged in as %s, uploading for %s)",
                    requester.device_id,
                    device_id,
                )
        else:
            device_id = requester.device_id

        if device_id is None:
            raise SynapseError(
                400, "To upload keys, you must pass device_id when authenticating"
            )

        result = await self.e2e_keys_handler.upload_keys_for_user(
            user_id, device_id, body
        )
        return 200, result


class KeyQueryServlet(RestServlet):
    """
    POST /keys/query HTTP/1.1
    Content-Type: application/json
    {
      "device_keys": {
        "<user_id>": ["<device_id>"]
    } }

    HTTP/1.1 200 OK
    {
      "device_keys": {
        "<user_id>": {
          "<device_id>": {
            "user_id": "<user_id>", // Duplicated to be signed
            "device_id": "<device_id>", // Duplicated to be signed
            "valid_until_ts": <millisecond_timestamp>,
            "algorithms": [ // List of supported algorithms
              "m.olm.curve25519-aes-sha2",
            ],
            "keys": { // Must include a ed25519 signing key
              "<algorithm>:<key_id>": "<key_base64>",
            },
            "signatures:" {
              // Must be signed with device's ed25519 key
              "<user_id>/<device_id>": {
                "<algorithm>:<key_id>": "<signature_base64>"
              }
              // Must be signed by this server.
              "<server_name>": {
                "<algorithm>:<key_id>": "<signature_base64>"
    } } } } } }
    """

    PATTERNS = client_patterns("/keys/query$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer):
        """
        super().__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()

    async def on_POST(self, request):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        user_id = requester.user.to_string()
        timeout = parse_integer(request, "timeout", 10 * 1000)
        body = parse_json_object_from_request(request)
        result = await self.e2e_keys_handler.query_devices(body, timeout, user_id)
        return 200, result


class KeyChangesServlet(RestServlet):
    """Returns the list of changes of keys between two stream tokens (may return
    spurious extra results, since we currently ignore the `to` param).

        GET /keys/changes?from=...&to=...

        200 OK
        { "changed": ["@foo:example.com"] }
    """

    PATTERNS = client_patterns("/keys/changes$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer):
        """
        super().__init__()
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()
        self.store = hs.get_datastore()

    async def on_GET(self, request):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        from_token_string = parse_string(request, "from")
        set_tag("from", from_token_string)

        # We want to enforce they do pass us one, but we ignore it and return
        # changes after the "to" as well as before.
        set_tag("to", parse_string(request, "to"))

        from_token = await StreamToken.from_string(self.store, from_token_string)

        user_id = requester.user.to_string()

        results = await self.device_handler.get_user_ids_changed(user_id, from_token)

        return 200, results


class OneTimeKeyServlet(RestServlet):
    """
    POST /keys/claim HTTP/1.1
    {
      "one_time_keys": {
        "<user_id>": {
          "<device_id>": "<algorithm>"
    } } }

    HTTP/1.1 200 OK
    {
      "one_time_keys": {
        "<user_id>": {
          "<device_id>": {
            "<algorithm>:<key_id>": "<key_base64>"
    } } } }

    """

    PATTERNS = client_patterns("/keys/claim$")

    def __init__(self, hs):
        super().__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()

    async def on_POST(self, request):
        await self.auth.get_user_by_req(request, allow_guest=True)
        timeout = parse_integer(request, "timeout", 10 * 1000)
        body = parse_json_object_from_request(request)
        result = await self.e2e_keys_handler.claim_one_time_keys(body, timeout)
        return 200, result


class SigningKeyUploadServlet(RestServlet):
    """
    POST /keys/device_signing/upload HTTP/1.1
    Content-Type: application/json

    {
    }
    """

    PATTERNS = client_patterns("/keys/device_signing/upload$", releases=())

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()
        self.auth_handler = hs.get_auth_handler()

    @interactive_auth_handler
    async def on_POST(self, request):
        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        await self.auth_handler.validate_user_via_ui_auth(
            requester,
            request,
            body,
            self.hs.get_ip_from_request(request),
            "add a device signing key to your account",
        )

        result = await self.e2e_keys_handler.upload_signing_keys_for_user(user_id, body)
        return 200, result


class SignaturesUploadServlet(RestServlet):
    """
    POST /keys/signatures/upload HTTP/1.1
    Content-Type: application/json

    {
      "@alice:example.com": {
        "<device_id>": {
          "user_id": "<user_id>",
          "device_id": "<device_id>",
          "algorithms": [
            "m.olm.curve25519-aes-sha2",
            "m.megolm.v1.aes-sha2"
          ],
          "keys": {
            "<algorithm>:<device_id>": "<key_base64>",
          },
          "signatures": {
            "<signing_user_id>": {
              "<algorithm>:<signing_key_base64>": "<signature_base64>>"
            }
          }
        }
      }
    }
    """

    PATTERNS = client_patterns("/keys/signatures/upload$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super().__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()

    async def on_POST(self, request):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        result = await self.e2e_keys_handler.upload_signatures_for_device_keys(
            user_id, body
        )
        return 200, result


def register_servlets(hs, http_server):
    KeyUploadServlet(hs).register(http_server)
    KeyQueryServlet(hs).register(http_server)
    KeyChangesServlet(hs).register(http_server)
    OneTimeKeyServlet(hs).register(http_server)
    SigningKeyUploadServlet(hs).register(http_server)
    SignaturesUploadServlet(hs).register(http_server)
