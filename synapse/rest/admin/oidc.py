# Copyright 2023 The Matrix.org Foundation C.I.C
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from http import HTTPStatus
from typing import TYPE_CHECKING, Dict, Tuple

from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.admin._base import admin_patterns, assert_requester_is_admin

if TYPE_CHECKING:
    from synapse.server import HomeServer


class OIDCTokenRevocationRestServlet(RestServlet):
    """
    Delete a given token introspection response - identified by the `jti` field - from the
    introspection token cache when a token is revoked at the authorizing server
    """

    PATTERNS = admin_patterns("/OIDC_token_revocation/(?P<token_id>[^/]*)")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        auth = hs.get_auth()

        # If this endpoint is loaded then we must have enabled delegated auth.
        from synapse.api.auth.msc3861_delegated import MSC3861DelegatedAuth

        assert isinstance(auth, MSC3861DelegatedAuth)

        self.auth = auth
        self.store = hs.get_datastores().main

    async def on_DELETE(
        self, request: SynapseRequest, token_id: str
    ) -> Tuple[HTTPStatus, Dict]:
        await assert_requester_is_admin(self.auth, request)

        self.auth._token_cache.invalidate(token_id)

        # make sure we invalidate the cache on any workers
        await self.store.stream_introspection_token_invalidation((token_id,))

        return HTTPStatus.OK, {}
