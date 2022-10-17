# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

""" This module contains REST servlets to do with rooms: /rooms/<paths> """
import logging
import re
from enum import Enum
from http import HTTPStatus
from typing import TYPE_CHECKING, Awaitable, Dict, List, Optional, Tuple
from urllib import parse as urlparse

from prometheus_client.core import Histogram

from twisted.web.server import Request

from synapse import event_auth
from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import (
    AuthError,
    Codes,
    InvalidClientCredentialsError,
    MissingClientTokenError,
    ShadowBanError,
    SynapseError,
    UnredactedContentDeletedError,
)
from synapse.api.filtering import Filter
from synapse.events.utils import format_event_for_client_v2
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    ResolveRoomIdMixin,
    RestServlet,
    assert_params_in_dict,
    parse_boolean,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
    parse_strings_from_args,
)
from synapse.http.site import SynapseRequest
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.logging.opentracing import set_tag
from synapse.rest.client._base import client_patterns
from synapse.rest.client.transactions import HttpTransactionCache
from synapse.storage.state import StateFilter
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict, StreamToken, ThirdPartyInstanceID, UserID
from synapse.util import json_decoder
from synapse.util.cancellation import cancellable
from synapse.util.stringutils import parse_and_validate_server_name, random_string

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class _RoomSize(Enum):
    """
    Enum to differentiate sizes of rooms. This is a pretty good approximation
    about how hard it will be to get events in the room. We could also look at
    room "complexity".
    """

    # This doesn't necessarily mean the room is a DM, just that there is a DM
    # amount of people there.
    DM_SIZE = "direct_message_size"
    SMALL = "small"
    SUBSTANTIAL = "substantial"
    LARGE = "large"

    @staticmethod
    def from_member_count(member_count: int) -> "_RoomSize":
        if member_count <= 2:
            return _RoomSize.DM_SIZE
        elif member_count < 100:
            return _RoomSize.SMALL
        elif member_count < 1000:
            return _RoomSize.SUBSTANTIAL
        else:
            return _RoomSize.LARGE


# This is an extra metric on top of `synapse_http_server_response_time_seconds`
# which times the same sort of thing but this one allows us to see values
# greater than 10s. We use a separate dedicated histogram with its own buckets
# so that we don't increase the cardinality of the general one because it's
# multiplied across hundreds of servlets.
messsages_response_timer = Histogram(
    "synapse_room_message_list_rest_servlet_response_time_seconds",
    "sec",
    # We have a label for room size so we can try to see a more realistic
    # picture of /messages response time for bigger rooms. We don't want the
    # tiny rooms that can always respond fast skewing our results when we're trying
    # to optimize the bigger cases.
    ["room_size"],
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
        20.0,
        30.0,
        60.0,
        80.0,
        100.0,
        120.0,
        150.0,
        180.0,
        "+Inf",
    ),
)


class TransactionRestServlet(RestServlet):
    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.txns = HttpTransactionCache(hs)


class RoomCreateRestServlet(TransactionRestServlet):
    # No PATTERN; we have custom dispatch rules here

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self._room_creation_handler = hs.get_room_creation_handler()
        self.auth = hs.get_auth()

    def register(self, http_server: HttpServer) -> None:
        PATTERNS = "/createRoom"
        register_txn_path(self, PATTERNS, http_server)

    def on_PUT(
        self, request: SynapseRequest, txn_id: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        set_tag("txn_id", txn_id)
        return self.txns.fetch_or_execute_request(request, self.on_POST, request)

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        info, _ = await self._room_creation_handler.create_room(
            requester, self.get_room_config(request)
        )

        return 200, info

    def get_room_config(self, request: Request) -> JsonDict:
        user_supplied_config = parse_json_object_from_request(request)
        return user_supplied_config


# TODO: Needs unit testing for generic events
class RoomStateEventRestServlet(TransactionRestServlet):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.event_creation_handler = hs.get_event_creation_handler()
        self.room_member_handler = hs.get_room_member_handler()
        self.message_handler = hs.get_message_handler()
        self.auth = hs.get_auth()

    def register(self, http_server: HttpServer) -> None:
        # /rooms/$roomid/state/$eventtype
        no_state_key = "/rooms/(?P<room_id>[^/]*)/state/(?P<event_type>[^/]*)$"

        # /rooms/$roomid/state/$eventtype/$statekey
        state_key = (
            "/rooms/(?P<room_id>[^/]*)/state/"
            "(?P<event_type>[^/]*)/(?P<state_key>[^/]*)$"
        )

        http_server.register_paths(
            "GET",
            client_patterns(state_key, v1=True),
            self.on_GET,
            self.__class__.__name__,
        )
        http_server.register_paths(
            "PUT",
            client_patterns(state_key, v1=True),
            self.on_PUT,
            self.__class__.__name__,
        )
        http_server.register_paths(
            "GET",
            client_patterns(no_state_key, v1=True),
            self.on_GET_no_state_key,
            self.__class__.__name__,
        )
        http_server.register_paths(
            "PUT",
            client_patterns(no_state_key, v1=True),
            self.on_PUT_no_state_key,
            self.__class__.__name__,
        )

    @cancellable
    def on_GET_no_state_key(
        self, request: SynapseRequest, room_id: str, event_type: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        return self.on_GET(request, room_id, event_type, "")

    def on_PUT_no_state_key(
        self, request: SynapseRequest, room_id: str, event_type: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        return self.on_PUT(request, room_id, event_type, "")

    @cancellable
    async def on_GET(
        self, request: SynapseRequest, room_id: str, event_type: str, state_key: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        format = parse_string(
            request, "format", default="content", allowed_values=["content", "event"]
        )

        msg_handler = self.message_handler
        data = await msg_handler.get_room_data(
            requester=requester,
            room_id=room_id,
            event_type=event_type,
            state_key=state_key,
        )

        if not data:
            raise SynapseError(404, "Event not found.", errcode=Codes.NOT_FOUND)

        if format == "event":
            event = format_event_for_client_v2(data.get_dict())
            return 200, event
        elif format == "content":
            return 200, data.get_dict()["content"]

        # Format must be event or content, per the parse_string call above.
        raise RuntimeError(f"Unknown format: {format:r}.")

    async def on_PUT(
        self,
        request: SynapseRequest,
        room_id: str,
        event_type: str,
        state_key: str,
        txn_id: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        if txn_id:
            set_tag("txn_id", txn_id)

        content = parse_json_object_from_request(request)

        origin_server_ts = None
        if requester.app_service:
            origin_server_ts = parse_integer(request, "ts")

        try:
            if event_type == EventTypes.Member:
                membership = content.get("membership", None)
                event_id, _ = await self.room_member_handler.update_membership(
                    requester,
                    target=UserID.from_string(state_key),
                    room_id=room_id,
                    action=membership,
                    content=content,
                    origin_server_ts=origin_server_ts,
                )
            else:
                event_dict: JsonDict = {
                    "type": event_type,
                    "content": content,
                    "room_id": room_id,
                    "sender": requester.user.to_string(),
                }

                if state_key is not None:
                    event_dict["state_key"] = state_key

                if origin_server_ts is not None:
                    event_dict["origin_server_ts"] = origin_server_ts

                (
                    event,
                    _,
                ) = await self.event_creation_handler.create_and_send_nonmember_event(
                    requester, event_dict, txn_id=txn_id
                )
                event_id = event.event_id
        except ShadowBanError:
            event_id = "$" + random_string(43)

        set_tag("event_id", event_id)
        ret = {"event_id": event_id}
        return 200, ret


# TODO: Needs unit testing for generic events + feedback
class RoomSendEventRestServlet(TransactionRestServlet):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.event_creation_handler = hs.get_event_creation_handler()
        self.auth = hs.get_auth()

    def register(self, http_server: HttpServer) -> None:
        # /rooms/$roomid/send/$event_type[/$txn_id]
        PATTERNS = "/rooms/(?P<room_id>[^/]*)/send/(?P<event_type>[^/]*)"
        register_txn_path(self, PATTERNS, http_server, with_get=True)

    async def on_POST(
        self,
        request: SynapseRequest,
        room_id: str,
        event_type: str,
        txn_id: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        content = parse_json_object_from_request(request)

        event_dict: JsonDict = {
            "type": event_type,
            "content": content,
            "room_id": room_id,
            "sender": requester.user.to_string(),
        }

        if requester.app_service:
            origin_server_ts = parse_integer(request, "ts")
            if origin_server_ts is not None:
                event_dict["origin_server_ts"] = origin_server_ts

        try:
            (
                event,
                _,
            ) = await self.event_creation_handler.create_and_send_nonmember_event(
                requester, event_dict, txn_id=txn_id
            )
            event_id = event.event_id
        except ShadowBanError:
            event_id = "$" + random_string(43)

        set_tag("event_id", event_id)
        return 200, {"event_id": event_id}

    def on_GET(
        self, request: SynapseRequest, room_id: str, event_type: str, txn_id: str
    ) -> Tuple[int, str]:
        return 200, "Not implemented"

    def on_PUT(
        self, request: SynapseRequest, room_id: str, event_type: str, txn_id: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        set_tag("txn_id", txn_id)

        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id, event_type, txn_id
        )


# TODO: Needs unit testing for room ID + alias joins
class JoinRoomAliasServlet(ResolveRoomIdMixin, TransactionRestServlet):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        super(ResolveRoomIdMixin, self).__init__(hs)  # ensure the Mixin is set up
        self.auth = hs.get_auth()

    def register(self, http_server: HttpServer) -> None:
        # /join/$room_identifier[/$txn_id]
        PATTERNS = "/join/(?P<room_identifier>[^/]*)"
        register_txn_path(self, PATTERNS, http_server)

    async def on_POST(
        self,
        request: SynapseRequest,
        room_identifier: str,
        txn_id: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        try:
            content = parse_json_object_from_request(request)
        except Exception:
            # Turns out we used to ignore the body entirely, and some clients
            # cheekily send invalid bodies.
            content = {}

        # twisted.web.server.Request.args is incorrectly defined as Optional[Any]
        args: Dict[bytes, List[bytes]] = request.args  # type: ignore
        remote_room_hosts = parse_strings_from_args(args, "server_name", required=False)
        room_id, remote_room_hosts = await self.resolve_room_id(
            room_identifier,
            remote_room_hosts,
        )

        await self.room_member_handler.update_membership(
            requester=requester,
            target=requester.user,
            room_id=room_id,
            action="join",
            txn_id=txn_id,
            remote_room_hosts=remote_room_hosts,
            content=content,
            third_party_signed=content.get("third_party_signed", None),
        )

        return 200, {"room_id": room_id}

    def on_PUT(
        self, request: SynapseRequest, room_identifier: str, txn_id: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        set_tag("txn_id", txn_id)

        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_identifier, txn_id
        )


# TODO: Needs unit testing
class PublicRoomListRestServlet(TransactionRestServlet):
    PATTERNS = client_patterns("/publicRooms$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.hs = hs
        self.auth = hs.get_auth()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        server = parse_string(request, "server")

        try:
            await self.auth.get_user_by_req(request, allow_guest=True)
        except InvalidClientCredentialsError as e:
            # Option to allow servers to require auth when accessing
            # /publicRooms via CS API. This is especially helpful in private
            # federations.
            if not self.hs.config.server.allow_public_rooms_without_auth:
                raise

            # We allow people to not be authed if they're just looking at our
            # room list, but require auth when we proxy the request.
            # In both cases we call the auth function, as that has the side
            # effect of logging who issued this request if an access token was
            # provided.
            if server:
                raise e

        limit: Optional[int] = parse_integer(request, "limit", 0)
        since_token = parse_string(request, "since")

        if limit == 0:
            # zero is a special value which corresponds to no limit.
            limit = None

        handler = self.hs.get_room_list_handler()
        if server and server != self.hs.config.server.server_name:
            # Ensure the server is valid.
            try:
                parse_and_validate_server_name(server)
            except ValueError:
                raise SynapseError(
                    400,
                    "Invalid server name: %s" % (server,),
                    Codes.INVALID_PARAM,
                )

            data = await handler.get_remote_public_room_list(
                server, limit=limit, since_token=since_token
            )
        else:
            data = await handler.get_local_public_room_list(
                limit=limit, since_token=since_token
            )

        return 200, data

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await self.auth.get_user_by_req(request, allow_guest=True)

        server = parse_string(request, "server")
        content = parse_json_object_from_request(request)

        limit: Optional[int] = int(content.get("limit", 100))
        since_token = content.get("since", None)
        search_filter = content.get("filter", None)

        include_all_networks = content.get("include_all_networks", False)
        third_party_instance_id = content.get("third_party_instance_id", None)

        if include_all_networks:
            network_tuple = None
            if third_party_instance_id is not None:
                raise SynapseError(
                    400, "Can't use include_all_networks with an explicit network"
                )
        elif third_party_instance_id is None:
            network_tuple = ThirdPartyInstanceID(None, None)
        else:
            network_tuple = ThirdPartyInstanceID.from_string(third_party_instance_id)

        if limit == 0:
            # zero is a special value which corresponds to no limit.
            limit = None

        handler = self.hs.get_room_list_handler()
        if server and server != self.hs.config.server.server_name:
            # Ensure the server is valid.
            try:
                parse_and_validate_server_name(server)
            except ValueError:
                raise SynapseError(
                    400,
                    "Invalid server name: %s" % (server,),
                    Codes.INVALID_PARAM,
                )

            data = await handler.get_remote_public_room_list(
                server,
                limit=limit,
                since_token=since_token,
                search_filter=search_filter,
                include_all_networks=include_all_networks,
                third_party_instance_id=third_party_instance_id,
            )

        else:
            data = await handler.get_local_public_room_list(
                limit=limit,
                since_token=since_token,
                search_filter=search_filter,
                network_tuple=network_tuple,
            )

        return 200, data


# TODO: Needs unit testing
class RoomMemberListRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/members$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.message_handler = hs.get_message_handler()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    @cancellable
    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        # TODO support Pagination stream API (limit/tokens)
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        handler = self.message_handler

        # request the state as of a given event, as identified by a stream token,
        # for consistency with /messages etc.
        # useful for getting the membership in retrospect as of a given /sync
        # response.
        at_token_string = parse_string(request, "at")
        if at_token_string is None:
            at_token = None
        else:
            at_token = await StreamToken.from_string(self.store, at_token_string)

        # let you filter down on particular memberships.
        # XXX: this may not be the best shape for this API - we could pass in a filter
        # instead, except filters aren't currently aware of memberships.
        # See https://github.com/matrix-org/matrix-doc/issues/1337 for more details.
        membership = parse_string(request, "membership")
        not_membership = parse_string(request, "not_membership")

        events = await handler.get_state_events(
            room_id=room_id,
            requester=requester,
            at_token=at_token,
            state_filter=StateFilter.from_types([(EventTypes.Member, None)]),
        )

        chunk = []

        for event in events:
            if (membership and event["content"].get("membership") != membership) or (
                not_membership and event["content"].get("membership") == not_membership
            ):
                continue
            chunk.append(event)

        return 200, {"chunk": chunk}


# deprecated in favour of /members?membership=join?
# except it does custom AS logic and has a simpler return format
class JoinedRoomMemberListRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/joined_members$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.message_handler = hs.get_message_handler()
        self.auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        users_with_profile = await self.message_handler.get_joined_members(
            requester, room_id
        )

        return 200, {"joined": users_with_profile}


# TODO: Needs better unit testing
class RoomMessageListRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/messages$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._hs = hs
        self.clock = hs.get_clock()
        self.pagination_handler = hs.get_pagination_handler()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        processing_start_time = self.clock.time_msec()
        # Fire off and hope that we get a result by the end.
        #
        # We're using the mypy type ignore comment because the `@cached`
        # decorator on `get_number_joined_users_in_room` doesn't play well with
        # the type system. Maybe in the future, it can use some ParamSpec
        # wizardry to fix it up.
        room_member_count_deferred = run_in_background(  # type: ignore[call-arg]
            self.store.get_number_joined_users_in_room,
            room_id,  # type: ignore[arg-type]
        )

        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        pagination_config = await PaginationConfig.from_request(
            self.store, request, default_limit=10
        )
        # Twisted will have processed the args by now.
        assert request.args is not None
        as_client_event = b"raw" not in request.args
        filter_str = parse_string(request, "filter", encoding="utf-8")
        if filter_str:
            filter_json = urlparse.unquote(filter_str)
            event_filter: Optional[Filter] = Filter(
                self._hs, json_decoder.decode(filter_json)
            )
            if (
                event_filter
                and event_filter.filter_json.get("event_format", "client")
                == "federation"
            ):
                as_client_event = False
        else:
            event_filter = None

        msgs = await self.pagination_handler.get_messages(
            room_id=room_id,
            requester=requester,
            pagin_config=pagination_config,
            as_client_event=as_client_event,
            event_filter=event_filter,
        )

        processing_end_time = self.clock.time_msec()
        room_member_count = await make_deferred_yieldable(room_member_count_deferred)
        messsages_response_timer.labels(
            room_size=_RoomSize.from_member_count(room_member_count)
        ).observe((processing_end_time - processing_start_time) / 1000)

        return 200, msgs


# TODO: Needs unit testing
class RoomStateRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/state$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.message_handler = hs.get_message_handler()
        self.auth = hs.get_auth()

    @cancellable
    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, List[JsonDict]]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        # Get all the current state for this room
        events = await self.message_handler.get_state_events(
            room_id=room_id,
            requester=requester,
        )
        return 200, events


# TODO: Needs unit testing
class RoomInitialSyncRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/initialSync$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.initial_sync_handler = hs.get_initial_sync_handler()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        pagination_config = await PaginationConfig.from_request(
            self.store, request, default_limit=10
        )
        content = await self.initial_sync_handler.room_initial_sync(
            room_id=room_id, requester=requester, pagin_config=pagination_config
        )
        return 200, content


class RoomEventServlet(RestServlet):
    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/event/(?P<event_id>[^/]*)$", v1=True
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.clock = hs.get_clock()
        self._store = hs.get_datastores().main
        self._state = hs.get_state_handler()
        self._storage_controllers = hs.get_storage_controllers()
        self.event_handler = hs.get_event_handler()
        self._event_serializer = hs.get_event_client_serializer()
        self._relations_handler = hs.get_relations_handler()
        self.auth = hs.get_auth()
        self.content_keep_ms = hs.config.server.redaction_retention_period
        self.msc2815_enabled = hs.config.experimental.msc2815_enabled

    async def on_GET(
        self, request: SynapseRequest, room_id: str, event_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        include_unredacted_content = self.msc2815_enabled and (
            parse_string(
                request,
                "fi.mau.msc2815.include_unredacted_content",
                allowed_values=("true", "false"),
            )
            == "true"
        )
        if include_unredacted_content and not await self.auth.is_server_admin(
            requester
        ):
            power_level_event = (
                await self._storage_controllers.state.get_current_state_event(
                    room_id, EventTypes.PowerLevels, ""
                )
            )

            auth_events = {}
            if power_level_event:
                auth_events[(EventTypes.PowerLevels, "")] = power_level_event

            redact_level = event_auth.get_named_level(auth_events, "redact", 50)
            user_level = event_auth.get_user_power_level(
                requester.user.to_string(), auth_events
            )
            if user_level < redact_level:
                raise SynapseError(
                    403,
                    "You don't have permission to view redacted events in this room.",
                    errcode=Codes.FORBIDDEN,
                )

        try:
            event = await self.event_handler.get_event(
                requester.user,
                room_id,
                event_id,
                show_redacted=include_unredacted_content,
            )
        except AuthError:
            # This endpoint is supposed to return a 404 when the requester does
            # not have permission to access the event
            # https://matrix.org/docs/spec/client_server/r0.5.0#get-matrix-client-r0-rooms-roomid-event-eventid
            raise SynapseError(404, "Event not found.", errcode=Codes.NOT_FOUND)

        if event:
            if include_unredacted_content and await self._store.have_censored_event(
                event_id
            ):
                raise UnredactedContentDeletedError(self.content_keep_ms)

            # Ensure there are bundled aggregations available.
            aggregations = await self._relations_handler.get_bundled_aggregations(
                [event], requester.user.to_string()
            )

            time_now = self.clock.time_msec()
            # per MSC2676, /rooms/{roomId}/event/{eventId}, should return the
            # *original* event, rather than the edited version
            event_dict = self._event_serializer.serialize_event(
                event, time_now, bundle_aggregations=aggregations, apply_edits=False
            )
            return 200, event_dict

        raise SynapseError(404, "Event not found.", errcode=Codes.NOT_FOUND)


class RoomEventContextServlet(RestServlet):
    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/context/(?P<event_id>[^/]*)$", v1=True
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._hs = hs
        self.clock = hs.get_clock()
        self.room_context_handler = hs.get_room_context_handler()
        self._event_serializer = hs.get_event_client_serializer()
        self.auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, room_id: str, event_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        limit = parse_integer(request, "limit", default=10)

        # picking the API shape for symmetry with /messages
        filter_str = parse_string(request, "filter", encoding="utf-8")
        if filter_str:
            filter_json = urlparse.unquote(filter_str)
            event_filter: Optional[Filter] = Filter(
                self._hs, json_decoder.decode(filter_json)
            )
        else:
            event_filter = None

        event_context = await self.room_context_handler.get_event_context(
            requester, room_id, event_id, limit, event_filter
        )

        if not event_context:
            raise SynapseError(404, "Event not found.", errcode=Codes.NOT_FOUND)

        time_now = self.clock.time_msec()
        results = {
            "events_before": self._event_serializer.serialize_events(
                event_context.events_before,
                time_now,
                bundle_aggregations=event_context.aggregations,
            ),
            "event": self._event_serializer.serialize_event(
                event_context.event,
                time_now,
                bundle_aggregations=event_context.aggregations,
            ),
            "events_after": self._event_serializer.serialize_events(
                event_context.events_after,
                time_now,
                bundle_aggregations=event_context.aggregations,
            ),
            "state": self._event_serializer.serialize_events(
                event_context.state, time_now
            ),
            "start": event_context.start,
            "end": event_context.end,
        }

        return 200, results


class RoomForgetRestServlet(TransactionRestServlet):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    def register(self, http_server: HttpServer) -> None:
        PATTERNS = "/rooms/(?P<room_id>[^/]*)/forget"
        register_txn_path(self, PATTERNS, http_server)

    async def on_POST(
        self, request: SynapseRequest, room_id: str, txn_id: Optional[str] = None
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=False)

        await self.room_member_handler.forget(user=requester.user, room_id=room_id)

        return 200, {}

    def on_PUT(
        self, request: SynapseRequest, room_id: str, txn_id: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        set_tag("txn_id", txn_id)

        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id, txn_id
        )


# TODO: Needs unit testing
class RoomMembershipRestServlet(TransactionRestServlet):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    def register(self, http_server: HttpServer) -> None:
        # /rooms/$roomid/[invite|join|leave]
        PATTERNS = (
            "/rooms/(?P<room_id>[^/]*)/"
            "(?P<membership_action>join|invite|leave|ban|unban|kick)"
        )
        register_txn_path(self, PATTERNS, http_server)

    async def on_POST(
        self,
        request: SynapseRequest,
        room_id: str,
        membership_action: str,
        txn_id: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        if requester.is_guest and membership_action not in {
            Membership.JOIN,
            Membership.LEAVE,
        }:
            raise AuthError(403, "Guest access not allowed")

        try:
            content = parse_json_object_from_request(request)
        except Exception:
            # Turns out we used to ignore the body entirely, and some clients
            # cheekily send invalid bodies.
            content = {}

        if membership_action == "invite" and all(
            key in content for key in ("medium", "address")
        ):
            if not all(key in content for key in ("id_server", "id_access_token")):
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    "`id_server` and `id_access_token` are required when doing 3pid invite",
                    Codes.MISSING_PARAM,
                )

            try:
                await self.room_member_handler.do_3pid_invite(
                    room_id,
                    requester.user,
                    content["medium"],
                    content["address"],
                    content["id_server"],
                    requester,
                    txn_id,
                    content["id_access_token"],
                )
            except ShadowBanError:
                # Pretend the request succeeded.
                pass
            return 200, {}

        target = requester.user
        if membership_action in ["invite", "ban", "unban", "kick"]:
            assert_params_in_dict(content, ["user_id"])
            target = UserID.from_string(content["user_id"])

        event_content = None
        if "reason" in content:
            event_content = {"reason": content["reason"]}

        try:
            await self.room_member_handler.update_membership(
                requester=requester,
                target=target,
                room_id=room_id,
                action=membership_action,
                txn_id=txn_id,
                third_party_signed=content.get("third_party_signed", None),
                content=event_content,
            )
        except ShadowBanError:
            # Pretend the request succeeded.
            pass

        return_value = {}

        if membership_action == "join":
            return_value["room_id"] = room_id

        return 200, return_value

    def on_PUT(
        self, request: SynapseRequest, room_id: str, membership_action: str, txn_id: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        set_tag("txn_id", txn_id)

        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id, membership_action, txn_id
        )


class RoomRedactEventRestServlet(TransactionRestServlet):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.event_creation_handler = hs.get_event_creation_handler()
        self.auth = hs.get_auth()

    def register(self, http_server: HttpServer) -> None:
        PATTERNS = "/rooms/(?P<room_id>[^/]*)/redact/(?P<event_id>[^/]*)"
        register_txn_path(self, PATTERNS, http_server)

    async def on_POST(
        self,
        request: SynapseRequest,
        room_id: str,
        event_id: str,
        txn_id: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        content = parse_json_object_from_request(request)

        try:
            (
                event,
                _,
            ) = await self.event_creation_handler.create_and_send_nonmember_event(
                requester,
                {
                    "type": EventTypes.Redaction,
                    "content": content,
                    "room_id": room_id,
                    "sender": requester.user.to_string(),
                    "redacts": event_id,
                },
                txn_id=txn_id,
            )
            event_id = event.event_id
        except ShadowBanError:
            event_id = "$" + random_string(43)

        set_tag("event_id", event_id)
        return 200, {"event_id": event_id}

    def on_PUT(
        self, request: SynapseRequest, room_id: str, event_id: str, txn_id: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        set_tag("txn_id", txn_id)

        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id, event_id, txn_id
        )


class RoomTypingRestServlet(RestServlet):
    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/typing/(?P<user_id>[^/]*)$", v1=True
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.presence_handler = hs.get_presence_handler()
        self.auth = hs.get_auth()

        # If we're not on the typing writer instance we should scream if we get
        # requests.
        self._is_typing_writer = (
            hs.get_instance_name() in hs.config.worker.writers.typing
        )

    async def on_PUT(
        self, request: SynapseRequest, room_id: str, user_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        if not self._is_typing_writer:
            raise Exception("Got /typing request on instance that is not typing writer")

        room_id = urlparse.unquote(room_id)
        target_user = UserID.from_string(urlparse.unquote(user_id))

        content = parse_json_object_from_request(request)

        await self.presence_handler.bump_presence_active_time(requester.user)

        # Limit timeout to stop people from setting silly typing timeouts.
        timeout = min(content.get("timeout", 30000), 120000)

        # Defer getting the typing handler since it will raise on workers.
        typing_handler = self.hs.get_typing_writer_handler()

        try:
            if content["typing"]:
                await typing_handler.started_typing(
                    target_user=target_user,
                    requester=requester,
                    room_id=room_id,
                    timeout=timeout,
                )
            else:
                await typing_handler.stopped_typing(
                    target_user=target_user, requester=requester, room_id=room_id
                )
        except ShadowBanError:
            # Pretend this worked without error.
            pass

        return 200, {}


class RoomAliasListServlet(RestServlet):
    PATTERNS = [
        re.compile(
            r"^/_matrix/client/unstable/org\.matrix\.msc2432"
            r"/rooms/(?P<room_id>[^/]*)/aliases"
        ),
    ] + list(client_patterns("/rooms/(?P<room_id>[^/]*)/aliases$", unstable=False))

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.directory_handler = hs.get_directory_handler()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        alias_list = await self.directory_handler.get_aliases_for_room(
            requester, room_id
        )

        return 200, {"aliases": alias_list}


class SearchRestServlet(RestServlet):
    PATTERNS = client_patterns("/search$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.search_handler = hs.get_search_handler()
        self.auth = hs.get_auth()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)

        batch = parse_string(request, "next_batch")
        results = await self.search_handler.search(requester.user, content, batch)

        return 200, results


class JoinedRoomsRestServlet(RestServlet):
    PATTERNS = client_patterns("/joined_rooms$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        room_ids = await self.store.get_rooms_for_user(requester.user.to_string())
        return 200, {"joined_rooms": list(room_ids)}


def register_txn_path(
    servlet: RestServlet,
    regex_string: str,
    http_server: HttpServer,
    with_get: bool = False,
) -> None:
    """Registers a transaction-based path.

    This registers two paths:
        PUT regex_string/$txnid
        POST regex_string

    Args:
        regex_string: The regex string to register. Must NOT have a
            trailing $ as this string will be appended to.
        http_server: The http_server to register paths with.
        with_get: True to also register respective GET paths for the PUTs.
    """
    on_POST = getattr(servlet, "on_POST", None)
    on_PUT = getattr(servlet, "on_PUT", None)
    if on_POST is None or on_PUT is None:
        raise RuntimeError("on_POST and on_PUT must exist when using register_txn_path")
    http_server.register_paths(
        "POST",
        client_patterns(regex_string + "$", v1=True),
        on_POST,
        servlet.__class__.__name__,
    )
    http_server.register_paths(
        "PUT",
        client_patterns(regex_string + "/(?P<txn_id>[^/]*)$", v1=True),
        on_PUT,
        servlet.__class__.__name__,
    )
    on_GET = getattr(servlet, "on_GET", None)
    if with_get:
        if on_GET is None:
            raise RuntimeError(
                "register_txn_path called with with_get = True, but no on_GET method exists"
            )
        http_server.register_paths(
            "GET",
            client_patterns(regex_string + "/(?P<txn_id>[^/]*)$", v1=True),
            on_GET,
            servlet.__class__.__name__,
        )


class TimestampLookupRestServlet(RestServlet):
    """
    API endpoint to fetch the `event_id` of the closest event to the given
    timestamp (`ts` query parameter) in the given direction (`dir` query
    parameter).

    Useful for cases like jump to date so you can start paginating messages from
    a given date in the archive.

    `ts` is a timestamp in milliseconds where we will find the closest event in
    the given direction.

    `dir` can be `f` or `b` to indicate forwards and backwards in time from the
    given timestamp.

    GET /_matrix/client/unstable/org.matrix.msc3030/rooms/<roomID>/timestamp_to_event?ts=<timestamp>&dir=<direction>
    {
        "event_id": ...
    }
    """

    PATTERNS = (
        re.compile(
            "^/_matrix/client/unstable/org.matrix.msc3030"
            "/rooms/(?P<room_id>[^/]*)/timestamp_to_event$"
        ),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main
        self.timestamp_lookup_handler = hs.get_timestamp_lookup_handler()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self._auth.get_user_by_req(request)
        await self._auth.check_user_in_room_or_world_readable(room_id, requester)

        timestamp = parse_integer(request, "ts", required=True)
        direction = parse_string(request, "dir", default="f", allowed_values=["f", "b"])

        (
            event_id,
            origin_server_ts,
        ) = await self.timestamp_lookup_handler.get_event_for_timestamp(
            requester, room_id, timestamp, direction
        )

        return 200, {
            "event_id": event_id,
            "origin_server_ts": origin_server_ts,
        }


class RoomHierarchyRestServlet(RestServlet):
    PATTERNS = (re.compile("^/_matrix/client/v1/rooms/(?P<room_id>[^/]*)/hierarchy$"),)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._auth = hs.get_auth()
        self._room_summary_handler = hs.get_room_summary_handler()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self._auth.get_user_by_req(request, allow_guest=True)

        max_depth = parse_integer(request, "max_depth")
        if max_depth is not None and max_depth < 0:
            raise SynapseError(
                400, "'max_depth' must be a non-negative integer", Codes.BAD_JSON
            )

        limit = parse_integer(request, "limit")
        if limit is not None and limit <= 0:
            raise SynapseError(
                400, "'limit' must be a positive integer", Codes.BAD_JSON
            )

        return 200, await self._room_summary_handler.get_room_hierarchy(
            requester,
            room_id,
            suggested_only=parse_boolean(request, "suggested_only", default=False),
            max_depth=max_depth,
            limit=limit,
            from_token=parse_string(request, "from"),
        )


class RoomSummaryRestServlet(ResolveRoomIdMixin, RestServlet):
    PATTERNS = (
        re.compile(
            "^/_matrix/client/unstable/im.nheko.summary"
            "/rooms/(?P<room_identifier>[^/]*)/summary$"
        ),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self._auth = hs.get_auth()
        self._room_summary_handler = hs.get_room_summary_handler()

    async def on_GET(
        self, request: SynapseRequest, room_identifier: str
    ) -> Tuple[int, JsonDict]:
        try:
            requester = await self._auth.get_user_by_req(request, allow_guest=True)
            requester_user_id: Optional[str] = requester.user.to_string()
        except MissingClientTokenError:
            # auth is optional
            requester_user_id = None

        # twisted.web.server.Request.args is incorrectly defined as Optional[Any]
        args: Dict[bytes, List[bytes]] = request.args  # type: ignore
        remote_room_hosts = parse_strings_from_args(args, "via", required=False)
        room_id, remote_room_hosts = await self.resolve_room_id(
            room_identifier,
            remote_room_hosts,
        )

        return 200, await self._room_summary_handler.get_room_summary(
            requester_user_id,
            room_id,
            remote_room_hosts,
        )


def register_servlets(
    hs: "HomeServer", http_server: HttpServer, is_worker: bool = False
) -> None:
    RoomStateEventRestServlet(hs).register(http_server)
    RoomMemberListRestServlet(hs).register(http_server)
    JoinedRoomMemberListRestServlet(hs).register(http_server)
    RoomMessageListRestServlet(hs).register(http_server)
    JoinRoomAliasServlet(hs).register(http_server)
    RoomMembershipRestServlet(hs).register(http_server)
    RoomSendEventRestServlet(hs).register(http_server)
    PublicRoomListRestServlet(hs).register(http_server)
    RoomStateRestServlet(hs).register(http_server)
    RoomRedactEventRestServlet(hs).register(http_server)
    RoomTypingRestServlet(hs).register(http_server)
    RoomEventContextServlet(hs).register(http_server)
    RoomHierarchyRestServlet(hs).register(http_server)
    if hs.config.experimental.msc3266_enabled:
        RoomSummaryRestServlet(hs).register(http_server)
    RoomEventServlet(hs).register(http_server)
    JoinedRoomsRestServlet(hs).register(http_server)
    RoomAliasListServlet(hs).register(http_server)
    SearchRestServlet(hs).register(http_server)
    RoomCreateRestServlet(hs).register(http_server)
    if hs.config.experimental.msc3030_enabled:
        TimestampLookupRestServlet(hs).register(http_server)

    # Some servlets only get registered for the main process.
    if not is_worker:
        RoomForgetRestServlet(hs).register(http_server)


def register_deprecated_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    RoomInitialSyncRestServlet(hs).register(http_server)
