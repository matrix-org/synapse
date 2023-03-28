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
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import SynapseError
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.admin import admin_patterns, assert_requester_is_admin
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ExperimentalFeaturesRestServlet(RestServlet):
    """
    Enable or disable an experimental feature or determine whether a given experimental
    feature is enabled
    """

    PATTERNS = admin_patterns(
        "/experimental_features/(?P<user_id>[^/]*)/(?P<feature>[^/]*)"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self.is_mine = hs.is_mine
        self.handler = hs.get_experimental_features_manager()

    async def on_GET(
        self,
        request: SynapseRequest,
        user_id: str,
        feature: str,
    ) -> Tuple[int, JsonDict]:
        """
        Checks if a given feature is enabled for a given user
        """
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "User must be local to check what experimental features are enabled.",
            )

        # do a basic validation of the given feature
        validated = feature in [
            "msc3026",
            "msc2654",
            "msc3881",
            "msc3967",
        ]

        if not validated:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Please provide a valid experimental feature."
            )

        enabled = await self.handler.get_feature_enabled(user_id, feature)

        return HTTPStatus.OK, {"user": user_id, "feature": feature, "enabled": enabled}

    async def on_PUT(
        self, request: SynapseRequest, user_id: str, feature: str
    ) -> Tuple[int, JsonDict]:
        """
        Enables a given feature for the requester
        """
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "User must be local to enable experimental features.",
            )

        # validate the feature
        validated = feature in [
            "msc3026",
            "msc2654",
            "msc3881",
            "msc3967",
        ]

        if not validated:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Please provide a valid experimental feature."
            )

        user, feature, enabled = await self.handler.set_feature_for_user(
            user_id, feature, True
        )

        return HTTPStatus.OK, {"user": user, "feature": feature, "enabled": enabled}

    async def on_DELETE(
        self, request: SynapseRequest, user_id: str, feature: str
    ) -> Tuple[int, JsonDict]:
        """
        Disables the requested feature for the given user
        """
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "User must be local to disable an experimental feature.",
            )

        # validate the feature
        validated = feature in [
            "msc3026",
            "msc2654",
            "msc3881",
            "msc3967",
        ]

        if not validated:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Please provide a valid experimental feature."
            )

        user, feature, enabled = await self.handler.set_feature_for_user(
            user_id, feature, False
        )

        return HTTPStatus.OK, {"user": user, "feature": feature, "enabled": enabled}
