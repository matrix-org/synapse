# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import re
from collections import Counter
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from synapse.api.errors import Codes, InvalidAPICallError, SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
)
from synapse.http.site import SynapseRequest
from synapse.logging.opentracing import log_kv, set_tag
from synapse.replication.http.devices import ReplicationUploadKeysForUserRestServlet
from synapse.rest.client._base import client_patterns, interactive_auth_handler
from synapse.types import JsonDict, StreamToken
from synapse.util.cancellation import cancellable

if TYPE_CHECKING:
    from synapse.server import HomeServer

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
                }
            }
        },
        "fallback_keys": {
            "<algorithm>:<device_id>": "<key_base64>",
            "signed_<algorithm>:<device_id>": {
                "fallback": true,
                "key": "<key_base64>",
                "signatures": {
                    "<user_id>": {
                        "<algorithm>:<device_id>": "<key_base64>"
                    }
                }
            }
        }
        "one_time_keys": {
            "<algorithm>:<key_id>": "<key_base64>"
        },
    }

    response, e.g.:

    {
        "one_time_key_counts": {
            "curve25519": 10,
            "signed_curve25519": 20
        }
    }

    """

    PATTERNS = client_patterns("/keys/upload(/(?P<device_id>[^/]+))?$")
    CATEGORY = "Encryption requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()
        self.device_handler = hs.get_device_handler()

        if hs.config.worker.worker_app is None:
            # if main process
            self.key_uploader = self.e2e_keys_handler.upload_keys_for_user
        else:
            # then a worker
            self.key_uploader = ReplicationUploadKeysForUserRestServlet.make_client(hs)

    async def on_POST(
        self, request: SynapseRequest, device_id: Optional[str]
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        if device_id is not None:
            # Providing the device_id should only be done for setting keys
            # for dehydrated devices; however, we allow it for any device for
            # compatibility with older clients.
            if requester.device_id is not None and device_id != requester.device_id:
                dehydrated_device = await self.device_handler.get_dehydrated_device(
                    user_id
                )
                if dehydrated_device is not None and device_id != dehydrated_device[0]:
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

        result = await self.key_uploader(
            user_id=user_id, device_id=device_id, keys=body
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
    CATEGORY = "Encryption requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()

    @cancellable
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        user_id = requester.user.to_string()
        device_id = requester.device_id
        timeout = parse_integer(request, "timeout", 10 * 1000)
        body = parse_json_object_from_request(request)

        device_keys = body.get("device_keys")
        if not isinstance(device_keys, dict):
            raise InvalidAPICallError("'device_keys' must be a JSON object")

        def is_list_of_strings(values: Any) -> bool:
            return isinstance(values, list) and all(isinstance(v, str) for v in values)

        if any(not is_list_of_strings(keys) for keys in device_keys.values()):
            raise InvalidAPICallError(
                "'device_keys' values must be a list of strings",
            )

        result = await self.e2e_keys_handler.query_devices(
            body, timeout, user_id, device_id
        )
        return 200, result


class KeyChangesServlet(RestServlet):
    """Returns the list of changes of keys between two stream tokens (may return
    spurious extra results, since we currently ignore the `to` param).

        GET /keys/changes?from=...&to=...

        200 OK
        { "changed": ["@foo:example.com"] }
    """

    PATTERNS = client_patterns("/keys/changes$")
    CATEGORY = "Encryption requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()
        self.store = hs.get_datastores().main

    @cancellable
    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        from_token_string = parse_string(request, "from", required=True)
        set_tag("from", from_token_string)

        # We want to enforce they do pass us one, but we ignore it and return
        # changes after the "to" as well as before.
        #
        # XXX This does not enforce that "to" is passed.
        set_tag("to", str(parse_string(request, "to")))

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
    CATEGORY = "Encryption requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        timeout = parse_integer(request, "timeout", 10 * 1000)
        body = parse_json_object_from_request(request)

        # Generate a count for each algorithm, which is hard-coded to 1.
        query: Dict[str, Dict[str, Dict[str, int]]] = {}
        for user_id, one_time_keys in body.get("one_time_keys", {}).items():
            for device_id, algorithm in one_time_keys.items():
                query.setdefault(user_id, {})[device_id] = {algorithm: 1}

        result = await self.e2e_keys_handler.claim_one_time_keys(
            query, requester.user, timeout, always_include_fallback_keys=False
        )
        return 200, result


class UnstableOneTimeKeyServlet(RestServlet):
    """
    Identical to the stable endpoint (OneTimeKeyServlet) except it allows for
    querying for multiple OTKs at once and always includes fallback keys in the
    response.

    POST /keys/claim HTTP/1.1
    {
      "one_time_keys": {
        "<user_id>": {
          "<device_id>": ["<algorithm>", ...]
    } } }

    HTTP/1.1 200 OK
    {
      "one_time_keys": {
        "<user_id>": {
          "<device_id>": {
            "<algorithm>:<key_id>": "<key_base64>"
    } } } }

    """

    PATTERNS = [re.compile(r"^/_matrix/client/unstable/org.matrix.msc3983/keys/claim$")]
    CATEGORY = "Encryption requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        timeout = parse_integer(request, "timeout", 10 * 1000)
        body = parse_json_object_from_request(request)

        # Generate a count for each algorithm.
        query: Dict[str, Dict[str, Dict[str, int]]] = {}
        for user_id, one_time_keys in body.get("one_time_keys", {}).items():
            for device_id, algorithms in one_time_keys.items():
                query.setdefault(user_id, {})[device_id] = Counter(algorithms)

        result = await self.e2e_keys_handler.claim_one_time_keys(
            query, requester.user, timeout, always_include_fallback_keys=True
        )
        return 200, result


class SigningKeyUploadServlet(RestServlet):
    """
    POST /keys/device_signing/upload HTTP/1.1
    Content-Type: application/json

    {
    }
    """

    PATTERNS = client_patterns("/keys/device_signing/upload$", releases=("v3",))

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()
        self.auth_handler = hs.get_auth_handler()

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        (
            is_cross_signing_setup,
            master_key_updatable_without_uia,
        ) = await self.e2e_keys_handler.check_cross_signing_setup(user_id)

        # Before MSC3967 we required UIA both when setting up cross signing for the
        # first time and when resetting the device signing key. With MSC3967 we only
        # require UIA when resetting cross-signing, and not when setting up the first
        # time. Because there is no UIA in MSC3861, for now we throw an error if the
        # user tries to reset the device signing key when MSC3861 is enabled, but allow
        # first-time setup.
        #
        # XXX: We now have a get-out clause by which MAS can temporarily mark the master
        # key as replaceable. It should do its own equivalent of user interactive auth
        # before doing so.
        if self.hs.config.experimental.msc3861.enabled:
            # The auth service has to explicitly mark the master key as replaceable
            # without UIA to reset the device signing key with MSC3861.
            if is_cross_signing_setup and not master_key_updatable_without_uia:
                raise SynapseError(
                    HTTPStatus.NOT_IMPLEMENTED,
                    "Resetting cross signing keys is not yet supported with MSC3861",
                    Codes.UNRECOGNIZED,
                )
            # But first-time setup is fine

        elif self.hs.config.experimental.msc3967_enabled:
            # If we already have a master key then cross signing is set up and we require UIA to reset
            if is_cross_signing_setup:
                await self.auth_handler.validate_user_via_ui_auth(
                    requester,
                    request,
                    body,
                    "reset the device signing key on your account",
                    # Do not allow skipping of UIA auth.
                    can_skip_ui_auth=False,
                )
            # Otherwise we don't require UIA since we are setting up cross signing for first time

        else:
            # Previous behaviour is to always require UIA but allow it to be skipped
            await self.auth_handler.validate_user_via_ui_auth(
                requester,
                request,
                body,
                "add a device signing key to your account",
                # Allow skipping of UI auth since this is frequently called directly
                # after login and it is silly to ask users to re-auth immediately.
                can_skip_ui_auth=True,
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

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        result = await self.e2e_keys_handler.upload_signatures_for_device_keys(
            user_id, body
        )
        return 200, result


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    KeyUploadServlet(hs).register(http_server)
    KeyQueryServlet(hs).register(http_server)
    KeyChangesServlet(hs).register(http_server)
    OneTimeKeyServlet(hs).register(http_server)
    if hs.config.experimental.msc3983_appservice_otk_claims:
        UnstableOneTimeKeyServlet(hs).register(http_server)
    if hs.config.worker.worker_app is None:
        SigningKeyUploadServlet(hs).register(http_server)
        SignaturesUploadServlet(hs).register(http_server)
