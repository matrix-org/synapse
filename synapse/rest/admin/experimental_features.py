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


from enum import Enum
from http import HTTPStatus
from typing import TYPE_CHECKING, Dict, Tuple

from synapse.api.errors import SynapseError
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.rest.admin import admin_patterns, assert_requester_is_admin
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ExperimentalFeature(str, Enum):
    """
    Currently supported per-user features
    """

    MSC3026 = "msc3026"
    MSC3881 = "msc3881"
    MSC3967 = "msc3967"


class ExperimentalFeaturesRestServlet(RestServlet):
    """
    Enable or disable experimental features for a user or determine which features are enabled
    for a given user
    """

    PATTERNS = admin_patterns("/experimental_features/(?P<user_id>[^/]*)")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self.is_mine = hs.is_mine

    async def on_GET(
        self,
        request: SynapseRequest,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        """
        List which features are enabled for a given user
        """
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "User must be local to check what experimental features are enabled.",
            )

        enabled_features = await self.store.list_enabled_features(user_id)

        user_features = {}
        for feature in ExperimentalFeature:
            if feature in enabled_features:
                user_features[feature] = True
            else:
                user_features[feature] = False
        return HTTPStatus.OK, {"features": user_features}

    async def on_PUT(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[HTTPStatus, Dict]:
        """
        Enable or disable the provided features for the requester
        """
        await assert_requester_is_admin(self.auth, request)

        body = parse_json_object_from_request(request)

        target_user = UserID.from_string(user_id)
        if not self.is_mine(target_user):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "User must be local to enable experimental features.",
            )

        features = body.get("features")
        if not features:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "You must provide features to set."
            )

        # validate the provided features
        validated_features = {}
        for feature, enabled in features.items():
            try:
                validated_feature = ExperimentalFeature(feature)
                validated_features[validated_feature] = enabled
            except ValueError:
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    f"{feature!r} is not recognised as a valid experimental feature.",
                )

        await self.store.set_features_for_user(user_id, validated_features)

        return HTTPStatus.OK, {}
