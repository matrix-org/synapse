#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import logging
from typing import Dict, List, Mapping, Optional, Sequence, Tuple, Type, Union

from typing_extensions import Literal

import synapse
from synapse.api.errors import Codes, SynapseError
from synapse.api.room_versions import RoomVersions
from synapse.api.urls import FEDERATION_UNSTABLE_PREFIX, FEDERATION_V2_PREFIX
from synapse.federation.transport.server._base import (
    Authenticator,
    BaseFederationServlet,
)
from synapse.http.servlet import (
    parse_boolean_from_args,
    parse_integer_from_args,
    parse_string_from_args,
    parse_strings_from_args,
)
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util.ratelimitutils import FederationRateLimiter
from synapse.util.versionstring import get_version_string

logger = logging.getLogger(__name__)


class BaseFederationServerServlet(BaseFederationServlet):
    """Abstract base class for federation servlet classes which provides a federation server handler.

    See BaseFederationServlet for more information.
    """

    def __init__(
        self,
        hs: HomeServer,
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_federation_server()


class FederationSendServlet(BaseFederationServerServlet):
    PATH = "/send/(?P<transaction_id>[^/]*)/?"

    # We ratelimit manually in the handler as we queue up the requests and we
    # don't want to fill up the ratelimiter with blocked requests.
    RATELIMIT = False

    # This is when someone is trying to send us a bunch of data.
    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        transaction_id: str,
    ) -> Tuple[int, JsonDict]:
        """Called on PUT /send/<transaction_id>/

        Args:
            transaction_id: The transaction_id associated with this request. This
                is *not* None.

        Returns:
            Tuple of `(code, response)`, where
            `response` is a python dict to be converted into JSON that is
            used as the response body.
        """
        # Parse the request
        try:
            transaction_data = content

            logger.debug("Decoded %s: %s", transaction_id, str(transaction_data))

            logger.info(
                "Received txn %s from %s. (PDUs: %d, EDUs: %d)",
                transaction_id,
                origin,
                len(transaction_data.get("pdus", [])),
                len(transaction_data.get("edus", [])),
            )

        except Exception as e:
            logger.exception(e)
            return 400, {"error": "Invalid transaction"}

        code, response = await self.handler.on_incoming_transaction(
            origin, transaction_id, self.server_name, transaction_data
        )

        return code, response


class FederationEventServlet(BaseFederationServerServlet):
    PATH = "/event/(?P<event_id>[^/]*)/?"

    # This is when someone asks for a data item for a given server data_id pair.
    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        event_id: str,
    ) -> Tuple[int, Union[JsonDict, str]]:
        return await self.handler.on_pdu_request(origin, event_id)


class FederationStateV1Servlet(BaseFederationServerServlet):
    PATH = "/state/(?P<room_id>[^/]*)/?"

    # This is when someone asks for all data for a given room.
    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        return await self.handler.on_room_state_request(
            origin,
            room_id,
            parse_string_from_args(query, "event_id", None, required=False),
        )


class FederationStateIdsServlet(BaseFederationServerServlet):
    PATH = "/state_ids/(?P<room_id>[^/]*)/?"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        return await self.handler.on_state_ids_request(
            origin,
            room_id,
            parse_string_from_args(query, "event_id", None, required=True),
        )


class FederationBackfillServlet(BaseFederationServerServlet):
    PATH = "/backfill/(?P<room_id>[^/]*)/?"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        versions = [x.decode("ascii") for x in query[b"v"]]
        limit = parse_integer_from_args(query, "limit", None)

        if not limit:
            return 400, {"error": "Did not include limit param"}

        return await self.handler.on_backfill_request(origin, room_id, versions, limit)


class FederationQueryServlet(BaseFederationServerServlet):
    PATH = "/query/(?P<query_type>[^/]*)"

    # This is when we receive a server-server Query
    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        query_type: str,
    ) -> Tuple[int, JsonDict]:
        args = {k.decode("utf8"): v[0].decode("utf-8") for k, v in query.items()}
        args["origin"] = origin
        return await self.handler.on_query_request(query_type, args)


class FederationMakeJoinServlet(BaseFederationServerServlet):
    PATH = "/make_join/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        room_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        """
        Args:
            origin: The authenticated server_name of the calling server

            content: (GETs don't have bodies)

            query: Query params from the request.

            **kwargs: the dict mapping keys to path components as specified in
                the path match regexp.

        Returns:
            Tuple of (response code, response object)
        """
        supported_versions = parse_strings_from_args(query, "ver", encoding="utf-8")
        if supported_versions is None:
            supported_versions = ["1"]

        result = await self.handler.on_make_join_request(
            origin, room_id, user_id, supported_versions=supported_versions
        )
        return 200, result


class FederationMakeLeaveServlet(BaseFederationServerServlet):
    PATH = "/make_leave/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        room_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        result = await self.handler.on_make_leave_request(origin, room_id, user_id)
        return 200, result


class FederationV1SendLeaveServlet(BaseFederationServerServlet):
    PATH = "/send_leave/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        room_id: str,
        event_id: str,
    ) -> Tuple[int, Tuple[int, JsonDict]]:
        result = await self.handler.on_send_leave_request(origin, content, room_id)
        return 200, (200, result)


class FederationV2SendLeaveServlet(BaseFederationServerServlet):
    PATH = "/send_leave/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    PREFIX = FEDERATION_V2_PREFIX

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        room_id: str,
        event_id: str,
    ) -> Tuple[int, JsonDict]:
        result = await self.handler.on_send_leave_request(origin, content, room_id)
        return 200, result


class FederationMakeKnockServlet(BaseFederationServerServlet):
    PATH = "/make_knock/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        room_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        # Retrieve the room versions the remote homeserver claims to support
        supported_versions = parse_strings_from_args(
            query, "ver", required=True, encoding="utf-8"
        )

        result = await self.handler.on_make_knock_request(
            origin, room_id, user_id, supported_versions=supported_versions
        )
        return 200, result


class FederationV1SendKnockServlet(BaseFederationServerServlet):
    PATH = "/send_knock/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        room_id: str,
        event_id: str,
    ) -> Tuple[int, JsonDict]:
        result = await self.handler.on_send_knock_request(origin, content, room_id)
        return 200, result


class FederationEventAuthServlet(BaseFederationServerServlet):
    PATH = "/event_auth/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        room_id: str,
        event_id: str,
    ) -> Tuple[int, JsonDict]:
        return await self.handler.on_event_auth(origin, room_id, event_id)


class FederationV1SendJoinServlet(BaseFederationServerServlet):
    PATH = "/send_join/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        room_id: str,
        event_id: str,
    ) -> Tuple[int, Tuple[int, JsonDict]]:
        # TODO(paul): assert that event_id parsed from path actually
        #   match those given in content
        result = await self.handler.on_send_join_request(origin, content, room_id)
        return 200, (200, result)


class FederationV2SendJoinServlet(BaseFederationServerServlet):
    PATH = "/send_join/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    PREFIX = FEDERATION_V2_PREFIX

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        room_id: str,
        event_id: str,
    ) -> Tuple[int, JsonDict]:
        # TODO(paul): assert that event_id parsed from path actually
        #   match those given in content
        result = await self.handler.on_send_join_request(origin, content, room_id)
        return 200, result


class FederationV1InviteServlet(BaseFederationServerServlet):
    PATH = "/invite/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        room_id: str,
        event_id: str,
    ) -> Tuple[int, Tuple[int, JsonDict]]:
        # We don't get a room version, so we have to assume its EITHER v1 or
        # v2. This is "fine" as the only difference between V1 and V2 is the
        # state resolution algorithm, and we don't use that for processing
        # invites
        result = await self.handler.on_invite_request(
            origin, content, room_version_id=RoomVersions.V1.identifier
        )

        # V1 federation API is defined to return a content of `[200, {...}]`
        # due to a historical bug.
        return 200, (200, result)


class FederationV2InviteServlet(BaseFederationServerServlet):
    PATH = "/invite/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    PREFIX = FEDERATION_V2_PREFIX

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        room_id: str,
        event_id: str,
    ) -> Tuple[int, JsonDict]:
        # TODO(paul): assert that room_id/event_id parsed from path actually
        #   match those given in content

        room_version = content["room_version"]
        event = content["event"]
        invite_room_state = content["invite_room_state"]

        # Synapse expects invite_room_state to be in unsigned, as it is in v1
        # API

        event.setdefault("unsigned", {})["invite_room_state"] = invite_room_state

        result = await self.handler.on_invite_request(
            origin, event, room_version_id=room_version
        )
        return 200, result


class FederationThirdPartyInviteExchangeServlet(BaseFederationServerServlet):
    PATH = "/exchange_third_party_invite/(?P<room_id>[^/]*)"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        await self.handler.on_exchange_third_party_invite_request(content)
        return 200, {}


class FederationClientKeysQueryServlet(BaseFederationServerServlet):
    PATH = "/user/keys/query"

    async def on_POST(
        self, origin: str, content: JsonDict, query: Dict[bytes, List[bytes]]
    ) -> Tuple[int, JsonDict]:
        return await self.handler.on_query_client_keys(origin, content)


class FederationUserDevicesQueryServlet(BaseFederationServerServlet):
    PATH = "/user/devices/(?P<user_id>[^/]*)"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        return await self.handler.on_query_user_devices(origin, user_id)


class FederationClientKeysClaimServlet(BaseFederationServerServlet):
    PATH = "/user/keys/claim"

    async def on_POST(
        self, origin: str, content: JsonDict, query: Dict[bytes, List[bytes]]
    ) -> Tuple[int, JsonDict]:
        response = await self.handler.on_claim_client_keys(origin, content)
        return 200, response


class FederationGetMissingEventsServlet(BaseFederationServerServlet):
    # TODO(paul): Why does this path alone end with "/?" optional?
    PATH = "/get_missing_events/(?P<room_id>[^/]*)/?"

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        limit = int(content.get("limit", 10))
        earliest_events = content.get("earliest_events", [])
        latest_events = content.get("latest_events", [])

        result = await self.handler.on_get_missing_events(
            origin,
            room_id=room_id,
            earliest_events=earliest_events,
            latest_events=latest_events,
            limit=limit,
        )

        return 200, result


class On3pidBindServlet(BaseFederationServerServlet):
    PATH = "/3pid/onbind"

    REQUIRE_AUTH = False

    async def on_POST(
        self, origin: Optional[str], content: JsonDict, query: Dict[bytes, List[bytes]]
    ) -> Tuple[int, JsonDict]:
        if "invites" in content:
            last_exception = None
            for invite in content["invites"]:
                try:
                    if "signed" not in invite or "token" not in invite["signed"]:
                        message = (
                            "Rejecting received notification of third-"
                            "party invite without signed: %s" % (invite,)
                        )
                        logger.info(message)
                        raise SynapseError(400, message)
                    await self.handler.exchange_third_party_invite(
                        invite["sender"],
                        invite["mxid"],
                        invite["room_id"],
                        invite["signed"],
                    )
                except Exception as e:
                    last_exception = e
            if last_exception:
                raise last_exception
        return 200, {}


class FederationVersionServlet(BaseFederationServlet):
    PATH = "/version"

    REQUIRE_AUTH = False

    async def on_GET(
        self,
        origin: Optional[str],
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
    ) -> Tuple[int, JsonDict]:
        return (
            200,
            {"server": {"name": "Synapse", "version": get_version_string(synapse)}},
        )


class FederationSpaceSummaryServlet(BaseFederationServlet):
    PREFIX = FEDERATION_UNSTABLE_PREFIX + "/org.matrix.msc2946"
    PATH = "/spaces/(?P<room_id>[^/]*)"

    def __init__(
        self,
        hs: HomeServer,
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_room_summary_handler()

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Mapping[bytes, Sequence[bytes]],
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        suggested_only = parse_boolean_from_args(query, "suggested_only", default=False)

        max_rooms_per_space = parse_integer_from_args(query, "max_rooms_per_space")
        if max_rooms_per_space is not None and max_rooms_per_space < 0:
            raise SynapseError(
                400,
                "Value for 'max_rooms_per_space' must be a non-negative integer",
                Codes.BAD_JSON,
            )

        exclude_rooms = parse_strings_from_args(query, "exclude_rooms", default=[])

        return 200, await self.handler.federation_space_summary(
            origin, room_id, suggested_only, max_rooms_per_space, exclude_rooms
        )

    # TODO When switching to the stable endpoint, remove the POST handler.
    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Mapping[bytes, Sequence[bytes]],
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        suggested_only = content.get("suggested_only", False)
        if not isinstance(suggested_only, bool):
            raise SynapseError(
                400, "'suggested_only' must be a boolean", Codes.BAD_JSON
            )

        exclude_rooms = content.get("exclude_rooms", [])
        if not isinstance(exclude_rooms, list) or any(
            not isinstance(x, str) for x in exclude_rooms
        ):
            raise SynapseError(400, "bad value for 'exclude_rooms'", Codes.BAD_JSON)

        max_rooms_per_space = content.get("max_rooms_per_space")
        if max_rooms_per_space is not None:
            if not isinstance(max_rooms_per_space, int):
                raise SynapseError(
                    400, "bad value for 'max_rooms_per_space'", Codes.BAD_JSON
                )
            if max_rooms_per_space < 0:
                raise SynapseError(
                    400,
                    "Value for 'max_rooms_per_space' must be a non-negative integer",
                    Codes.BAD_JSON,
                )

        return 200, await self.handler.federation_space_summary(
            origin, room_id, suggested_only, max_rooms_per_space, exclude_rooms
        )


class FederationRoomHierarchyServlet(BaseFederationServlet):
    PREFIX = FEDERATION_UNSTABLE_PREFIX + "/org.matrix.msc2946"
    PATH = "/hierarchy/(?P<room_id>[^/]*)"

    def __init__(
        self,
        hs: HomeServer,
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_room_summary_handler()

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Mapping[bytes, Sequence[bytes]],
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        suggested_only = parse_boolean_from_args(query, "suggested_only", default=False)
        return 200, await self.handler.get_federation_hierarchy(
            origin, room_id, suggested_only
        )


class RoomComplexityServlet(BaseFederationServlet):
    """
    Indicates to other servers how complex (and therefore likely
    resource-intensive) a public room this server knows about is.
    """

    PATH = "/rooms/(?P<room_id>[^/]*)/complexity"
    PREFIX = FEDERATION_UNSTABLE_PREFIX

    def __init__(
        self,
        hs: HomeServer,
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self._store = self.hs.get_datastore()

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        is_public = await self._store.is_room_world_readable_or_publicly_joinable(
            room_id
        )

        if not is_public:
            raise SynapseError(404, "Room not found", errcode=Codes.INVALID_PARAM)

        complexity = await self._store.get_room_complexity(room_id)
        return 200, complexity


FEDERATION_SERVLET_CLASSES: Tuple[Type[BaseFederationServlet], ...] = (
    FederationSendServlet,
    FederationEventServlet,
    FederationStateV1Servlet,
    FederationStateIdsServlet,
    FederationBackfillServlet,
    FederationQueryServlet,
    FederationMakeJoinServlet,
    FederationMakeLeaveServlet,
    FederationEventServlet,
    FederationV1SendJoinServlet,
    FederationV2SendJoinServlet,
    FederationV1SendLeaveServlet,
    FederationV2SendLeaveServlet,
    FederationV1InviteServlet,
    FederationV2InviteServlet,
    FederationGetMissingEventsServlet,
    FederationEventAuthServlet,
    FederationClientKeysQueryServlet,
    FederationUserDevicesQueryServlet,
    FederationClientKeysClaimServlet,
    FederationThirdPartyInviteExchangeServlet,
    On3pidBindServlet,
    FederationVersionServlet,
    RoomComplexityServlet,
    FederationSpaceSummaryServlet,
    FederationRoomHierarchyServlet,
    FederationV1SendKnockServlet,
    FederationMakeKnockServlet,
)
