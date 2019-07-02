# -*- coding: utf-8 -*-
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

from six.moves.urllib import parse as urlparse

from canonicaljson import json

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.api.filtering import Filter
from synapse.events.utils import format_event_for_client_v2
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
)
from synapse.rest.client.transactions import HttpTransactionCache
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.storage.state import StateFilter
from synapse.streams.config import PaginationConfig
from synapse.types import RoomAlias, RoomID, StreamToken, ThirdPartyInstanceID, UserID

logger = logging.getLogger(__name__)


class TransactionRestServlet(RestServlet):
    def __init__(self, hs):
        super(TransactionRestServlet, self).__init__()
        self.txns = HttpTransactionCache(hs)


class RoomCreateRestServlet(TransactionRestServlet):
    # No PATTERN; we have custom dispatch rules here

    def __init__(self, hs):
        super(RoomCreateRestServlet, self).__init__(hs)
        self._room_creation_handler = hs.get_room_creation_handler()
        self.auth = hs.get_auth()

    def register(self, http_server):
        PATTERNS = "/createRoom"
        register_txn_path(self, PATTERNS, http_server)
        # define CORS for all of /rooms in RoomCreateRestServlet for simplicity
        http_server.register_paths(
            "OPTIONS", client_patterns("/rooms(?:/.*)?$", v1=True), self.on_OPTIONS
        )
        # define CORS for /createRoom[/txnid]
        http_server.register_paths(
            "OPTIONS", client_patterns("/createRoom(?:/.*)?$", v1=True), self.on_OPTIONS
        )

    def on_PUT(self, request, txn_id):
        return self.txns.fetch_or_execute_request(request, self.on_POST, request)

    @defer.inlineCallbacks
    def on_POST(self, request):
        requester = yield self.auth.get_user_by_req(request)

        info = yield self._room_creation_handler.create_room(
            requester, self.get_room_config(request)
        )

        defer.returnValue((200, info))

    def get_room_config(self, request):
        user_supplied_config = parse_json_object_from_request(request)
        return user_supplied_config

    def on_OPTIONS(self, request):
        return (200, {})


# TODO: Needs unit testing for generic events
class RoomStateEventRestServlet(TransactionRestServlet):
    def __init__(self, hs):
        super(RoomStateEventRestServlet, self).__init__(hs)
        self.handlers = hs.get_handlers()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.room_member_handler = hs.get_room_member_handler()
        self.message_handler = hs.get_message_handler()
        self.auth = hs.get_auth()

    def register(self, http_server):
        # /room/$roomid/state/$eventtype
        no_state_key = "/rooms/(?P<room_id>[^/]*)/state/(?P<event_type>[^/]*)$"

        # /room/$roomid/state/$eventtype/$statekey
        state_key = (
            "/rooms/(?P<room_id>[^/]*)/state/"
            "(?P<event_type>[^/]*)/(?P<state_key>[^/]*)$"
        )

        http_server.register_paths(
            "GET", client_patterns(state_key, v1=True), self.on_GET
        )
        http_server.register_paths(
            "PUT", client_patterns(state_key, v1=True), self.on_PUT
        )
        http_server.register_paths(
            "GET", client_patterns(no_state_key, v1=True), self.on_GET_no_state_key
        )
        http_server.register_paths(
            "PUT", client_patterns(no_state_key, v1=True), self.on_PUT_no_state_key
        )

    def on_GET_no_state_key(self, request, room_id, event_type):
        return self.on_GET(request, room_id, event_type, "")

    def on_PUT_no_state_key(self, request, room_id, event_type):
        return self.on_PUT(request, room_id, event_type, "")

    @defer.inlineCallbacks
    def on_GET(self, request, room_id, event_type, state_key):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        format = parse_string(
            request, "format", default="content", allowed_values=["content", "event"]
        )

        msg_handler = self.message_handler
        data = yield msg_handler.get_room_data(
            user_id=requester.user.to_string(),
            room_id=room_id,
            event_type=event_type,
            state_key=state_key,
            is_guest=requester.is_guest,
        )

        if not data:
            raise SynapseError(404, "Event not found.", errcode=Codes.NOT_FOUND)

        if format == "event":
            event = format_event_for_client_v2(data.get_dict())
            defer.returnValue((200, event))
        elif format == "content":
            defer.returnValue((200, data.get_dict()["content"]))

    @defer.inlineCallbacks
    def on_PUT(self, request, room_id, event_type, state_key, txn_id=None):
        requester = yield self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)

        event_dict = {
            "type": event_type,
            "content": content,
            "room_id": room_id,
            "sender": requester.user.to_string(),
        }

        if state_key is not None:
            event_dict["state_key"] = state_key

        if event_type == EventTypes.Member:
            membership = content.get("membership", None)
            event = yield self.room_member_handler.update_membership(
                requester,
                target=UserID.from_string(state_key),
                room_id=room_id,
                action=membership,
                content=content,
            )
        else:
            event = yield self.event_creation_handler.create_and_send_nonmember_event(
                requester, event_dict, txn_id=txn_id
            )

        ret = {}
        if event:
            ret = {"event_id": event.event_id}
        defer.returnValue((200, ret))


# TODO: Needs unit testing for generic events + feedback
class RoomSendEventRestServlet(TransactionRestServlet):
    def __init__(self, hs):
        super(RoomSendEventRestServlet, self).__init__(hs)
        self.event_creation_handler = hs.get_event_creation_handler()
        self.auth = hs.get_auth()

    def register(self, http_server):
        # /rooms/$roomid/send/$event_type[/$txn_id]
        PATTERNS = "/rooms/(?P<room_id>[^/]*)/send/(?P<event_type>[^/]*)"
        register_txn_path(self, PATTERNS, http_server, with_get=True)

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, event_type, txn_id=None):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        content = parse_json_object_from_request(request)

        event_dict = {
            "type": event_type,
            "content": content,
            "room_id": room_id,
            "sender": requester.user.to_string(),
        }

        if b"ts" in request.args and requester.app_service:
            event_dict["origin_server_ts"] = parse_integer(request, "ts", 0)

        event = yield self.event_creation_handler.create_and_send_nonmember_event(
            requester, event_dict, txn_id=txn_id
        )

        defer.returnValue((200, {"event_id": event.event_id}))

    def on_GET(self, request, room_id, event_type, txn_id):
        return (200, "Not implemented")

    def on_PUT(self, request, room_id, event_type, txn_id):
        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id, event_type, txn_id
        )


# TODO: Needs unit testing for room ID + alias joins
class JoinRoomAliasServlet(TransactionRestServlet):
    def __init__(self, hs):
        super(JoinRoomAliasServlet, self).__init__(hs)
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    def register(self, http_server):
        # /join/$room_identifier[/$txn_id]
        PATTERNS = "/join/(?P<room_identifier>[^/]*)"
        register_txn_path(self, PATTERNS, http_server)

    @defer.inlineCallbacks
    def on_POST(self, request, room_identifier, txn_id=None):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)

        try:
            content = parse_json_object_from_request(request)
        except Exception:
            # Turns out we used to ignore the body entirely, and some clients
            # cheekily send invalid bodies.
            content = {}

        if RoomID.is_valid(room_identifier):
            room_id = room_identifier
            try:
                remote_room_hosts = [
                    x.decode("ascii") for x in request.args[b"server_name"]
                ]
            except Exception:
                remote_room_hosts = None
        elif RoomAlias.is_valid(room_identifier):
            handler = self.room_member_handler
            room_alias = RoomAlias.from_string(room_identifier)
            room_id, remote_room_hosts = yield handler.lookup_room_alias(room_alias)
            room_id = room_id.to_string()
        else:
            raise SynapseError(
                400, "%s was not legal room ID or room alias" % (room_identifier,)
            )

        yield self.room_member_handler.update_membership(
            requester=requester,
            target=requester.user,
            room_id=room_id,
            action="join",
            txn_id=txn_id,
            remote_room_hosts=remote_room_hosts,
            content=content,
            third_party_signed=content.get("third_party_signed", None),
        )

        defer.returnValue((200, {"room_id": room_id}))

    def on_PUT(self, request, room_identifier, txn_id):
        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_identifier, txn_id
        )


# TODO: Needs unit testing
class PublicRoomListRestServlet(TransactionRestServlet):
    PATTERNS = client_patterns("/publicRooms$", v1=True)

    def __init__(self, hs):
        super(PublicRoomListRestServlet, self).__init__(hs)
        self.hs = hs
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request):
        server = parse_string(request, "server", default=None)

        try:
            yield self.auth.get_user_by_req(request, allow_guest=True)
        except AuthError as e:
            # Option to allow servers to require auth when accessing
            # /publicRooms via CS API. This is especially helpful in private
            # federations.
            if not self.hs.config.allow_public_rooms_without_auth:
                raise

            # We allow people to not be authed if they're just looking at our
            # room list, but require auth when we proxy the request.
            # In both cases we call the auth function, as that has the side
            # effect of logging who issued this request if an access token was
            # provided.
            if server:
                raise e
            else:
                pass

        limit = parse_integer(request, "limit", 0)
        since_token = parse_string(request, "since", None)

        handler = self.hs.get_room_list_handler()
        if server:
            data = yield handler.get_remote_public_room_list(
                server, limit=limit, since_token=since_token
            )
        else:
            data = yield handler.get_local_public_room_list(
                limit=limit, since_token=since_token
            )

        defer.returnValue((200, data))

    @defer.inlineCallbacks
    def on_POST(self, request):
        yield self.auth.get_user_by_req(request, allow_guest=True)

        server = parse_string(request, "server", default=None)
        content = parse_json_object_from_request(request)

        limit = int(content.get("limit", 100))
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

        handler = self.hs.get_room_list_handler()
        if server:
            data = yield handler.get_remote_public_room_list(
                server,
                limit=limit,
                since_token=since_token,
                search_filter=search_filter,
                include_all_networks=include_all_networks,
                third_party_instance_id=third_party_instance_id,
            )
        else:
            data = yield handler.get_local_public_room_list(
                limit=limit,
                since_token=since_token,
                search_filter=search_filter,
                network_tuple=network_tuple,
            )

        defer.returnValue((200, data))


# TODO: Needs unit testing
class RoomMemberListRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/members$", v1=True)

    def __init__(self, hs):
        super(RoomMemberListRestServlet, self).__init__()
        self.message_handler = hs.get_message_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        # TODO support Pagination stream API (limit/tokens)
        requester = yield self.auth.get_user_by_req(request)
        handler = self.message_handler

        # request the state as of a given event, as identified by a stream token,
        # for consistency with /messages etc.
        # useful for getting the membership in retrospect as of a given /sync
        # response.
        at_token_string = parse_string(request, "at")
        if at_token_string is None:
            at_token = None
        else:
            at_token = StreamToken.from_string(at_token_string)

        # let you filter down on particular memberships.
        # XXX: this may not be the best shape for this API - we could pass in a filter
        # instead, except filters aren't currently aware of memberships.
        # See https://github.com/matrix-org/matrix-doc/issues/1337 for more details.
        membership = parse_string(request, "membership")
        not_membership = parse_string(request, "not_membership")

        events = yield handler.get_state_events(
            room_id=room_id,
            user_id=requester.user.to_string(),
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

        defer.returnValue((200, {"chunk": chunk}))


# deprecated in favour of /members?membership=join?
# except it does custom AS logic and has a simpler return format
class JoinedRoomMemberListRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/joined_members$", v1=True)

    def __init__(self, hs):
        super(JoinedRoomMemberListRestServlet, self).__init__()
        self.message_handler = hs.get_message_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request)

        users_with_profile = yield self.message_handler.get_joined_members(
            requester, room_id
        )

        defer.returnValue((200, {"joined": users_with_profile}))


# TODO: Needs better unit testing
class RoomMessageListRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/messages$", v1=True)

    def __init__(self, hs):
        super(RoomMessageListRestServlet, self).__init__()
        self.pagination_handler = hs.get_pagination_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        pagination_config = PaginationConfig.from_request(request, default_limit=10)
        as_client_event = b"raw" not in request.args
        filter_bytes = parse_string(request, b"filter", encoding=None)
        if filter_bytes:
            filter_json = urlparse.unquote(filter_bytes.decode("UTF-8"))
            event_filter = Filter(json.loads(filter_json))
            if event_filter.filter_json.get("event_format", "client") == "federation":
                as_client_event = False
        else:
            event_filter = None
        msgs = yield self.pagination_handler.get_messages(
            room_id=room_id,
            requester=requester,
            pagin_config=pagination_config,
            as_client_event=as_client_event,
            event_filter=event_filter,
        )

        defer.returnValue((200, msgs))


# TODO: Needs unit testing
class RoomStateRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/state$", v1=True)

    def __init__(self, hs):
        super(RoomStateRestServlet, self).__init__()
        self.message_handler = hs.get_message_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        # Get all the current state for this room
        events = yield self.message_handler.get_state_events(
            room_id=room_id,
            user_id=requester.user.to_string(),
            is_guest=requester.is_guest,
        )
        defer.returnValue((200, events))


# TODO: Needs unit testing
class RoomInitialSyncRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/initialSync$", v1=True)

    def __init__(self, hs):
        super(RoomInitialSyncRestServlet, self).__init__()
        self.initial_sync_handler = hs.get_initial_sync_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        pagination_config = PaginationConfig.from_request(request)
        content = yield self.initial_sync_handler.room_initial_sync(
            room_id=room_id, requester=requester, pagin_config=pagination_config
        )
        defer.returnValue((200, content))


class RoomEventServlet(RestServlet):
    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/event/(?P<event_id>[^/]*)$", v1=True
    )

    def __init__(self, hs):
        super(RoomEventServlet, self).__init__()
        self.clock = hs.get_clock()
        self.event_handler = hs.get_event_handler()
        self._event_serializer = hs.get_event_client_serializer()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id, event_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        event = yield self.event_handler.get_event(requester.user, room_id, event_id)

        time_now = self.clock.time_msec()
        if event:
            event = yield self._event_serializer.serialize_event(event, time_now)
            defer.returnValue((200, event))
        else:
            defer.returnValue((404, "Event not found."))


class RoomEventContextServlet(RestServlet):
    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/context/(?P<event_id>[^/]*)$", v1=True
    )

    def __init__(self, hs):
        super(RoomEventContextServlet, self).__init__()
        self.clock = hs.get_clock()
        self.room_context_handler = hs.get_room_context_handler()
        self._event_serializer = hs.get_event_client_serializer()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id, event_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)

        limit = parse_integer(request, "limit", default=10)

        # picking the API shape for symmetry with /messages
        filter_bytes = parse_string(request, "filter")
        if filter_bytes:
            filter_json = urlparse.unquote(filter_bytes)
            event_filter = Filter(json.loads(filter_json))
        else:
            event_filter = None

        results = yield self.room_context_handler.get_event_context(
            requester.user, room_id, event_id, limit, event_filter
        )

        if not results:
            raise SynapseError(404, "Event not found.", errcode=Codes.NOT_FOUND)

        time_now = self.clock.time_msec()
        results["events_before"] = yield self._event_serializer.serialize_events(
            results["events_before"], time_now
        )
        results["event"] = yield self._event_serializer.serialize_event(
            results["event"], time_now
        )
        results["events_after"] = yield self._event_serializer.serialize_events(
            results["events_after"], time_now
        )
        results["state"] = yield self._event_serializer.serialize_events(
            results["state"], time_now
        )

        defer.returnValue((200, results))


class RoomForgetRestServlet(TransactionRestServlet):
    def __init__(self, hs):
        super(RoomForgetRestServlet, self).__init__(hs)
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    def register(self, http_server):
        PATTERNS = "/rooms/(?P<room_id>[^/]*)/forget"
        register_txn_path(self, PATTERNS, http_server)

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, txn_id=None):
        requester = yield self.auth.get_user_by_req(request, allow_guest=False)

        yield self.room_member_handler.forget(user=requester.user, room_id=room_id)

        defer.returnValue((200, {}))

    def on_PUT(self, request, room_id, txn_id):
        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id, txn_id
        )


# TODO: Needs unit testing
class RoomMembershipRestServlet(TransactionRestServlet):
    def __init__(self, hs):
        super(RoomMembershipRestServlet, self).__init__(hs)
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    def register(self, http_server):
        # /rooms/$roomid/[invite|join|leave]
        PATTERNS = (
            "/rooms/(?P<room_id>[^/]*)/"
            "(?P<membership_action>join|invite|leave|ban|unban|kick)"
        )
        register_txn_path(self, PATTERNS, http_server)

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, membership_action, txn_id=None):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)

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

        if membership_action == "invite" and self._has_3pid_invite_keys(content):
            yield self.room_member_handler.do_3pid_invite(
                room_id,
                requester.user,
                content["medium"],
                content["address"],
                content["id_server"],
                requester,
                txn_id,
            )
            defer.returnValue((200, {}))
            return

        target = requester.user
        if membership_action in ["invite", "ban", "unban", "kick"]:
            assert_params_in_dict(content, ["user_id"])
            target = UserID.from_string(content["user_id"])

        event_content = None
        if "reason" in content and membership_action in ["kick", "ban"]:
            event_content = {"reason": content["reason"]}

        yield self.room_member_handler.update_membership(
            requester=requester,
            target=target,
            room_id=room_id,
            action=membership_action,
            txn_id=txn_id,
            third_party_signed=content.get("third_party_signed", None),
            content=event_content,
        )

        return_value = {}

        if membership_action == "join":
            return_value["room_id"] = room_id

        defer.returnValue((200, return_value))

    def _has_3pid_invite_keys(self, content):
        for key in {"id_server", "medium", "address"}:
            if key not in content:
                return False
        return True

    def on_PUT(self, request, room_id, membership_action, txn_id):
        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id, membership_action, txn_id
        )


class RoomRedactEventRestServlet(TransactionRestServlet):
    def __init__(self, hs):
        super(RoomRedactEventRestServlet, self).__init__(hs)
        self.handlers = hs.get_handlers()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.auth = hs.get_auth()

    def register(self, http_server):
        PATTERNS = "/rooms/(?P<room_id>[^/]*)/redact/(?P<event_id>[^/]*)"
        register_txn_path(self, PATTERNS, http_server)

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, event_id, txn_id=None):
        requester = yield self.auth.get_user_by_req(request)
        content = parse_json_object_from_request(request)

        event = yield self.event_creation_handler.create_and_send_nonmember_event(
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

        defer.returnValue((200, {"event_id": event.event_id}))

    def on_PUT(self, request, room_id, event_id, txn_id):
        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id, event_id, txn_id
        )


class RoomTypingRestServlet(RestServlet):
    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/typing/(?P<user_id>[^/]*)$", v1=True
    )

    def __init__(self, hs):
        super(RoomTypingRestServlet, self).__init__()
        self.presence_handler = hs.get_presence_handler()
        self.typing_handler = hs.get_typing_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_PUT(self, request, room_id, user_id):
        requester = yield self.auth.get_user_by_req(request)

        room_id = urlparse.unquote(room_id)
        target_user = UserID.from_string(urlparse.unquote(user_id))

        content = parse_json_object_from_request(request)

        yield self.presence_handler.bump_presence_active_time(requester.user)

        # Limit timeout to stop people from setting silly typing timeouts.
        timeout = min(content.get("timeout", 30000), 120000)

        if content["typing"]:
            yield self.typing_handler.started_typing(
                target_user=target_user,
                auth_user=requester.user,
                room_id=room_id,
                timeout=timeout,
            )
        else:
            yield self.typing_handler.stopped_typing(
                target_user=target_user, auth_user=requester.user, room_id=room_id
            )

        defer.returnValue((200, {}))


class SearchRestServlet(RestServlet):
    PATTERNS = client_patterns("/search$", v1=True)

    def __init__(self, hs):
        super(SearchRestServlet, self).__init__()
        self.handlers = hs.get_handlers()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_POST(self, request):
        requester = yield self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)

        batch = parse_string(request, "next_batch")
        results = yield self.handlers.search_handler.search(
            requester.user, content, batch
        )

        defer.returnValue((200, results))


class JoinedRoomsRestServlet(RestServlet):
    PATTERNS = client_patterns("/joined_rooms$", v1=True)

    def __init__(self, hs):
        super(JoinedRoomsRestServlet, self).__init__()
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)

        room_ids = yield self.store.get_rooms_for_user(requester.user.to_string())
        defer.returnValue((200, {"joined_rooms": list(room_ids)}))


def register_txn_path(servlet, regex_string, http_server, with_get=False):
    """Registers a transaction-based path.

    This registers two paths:
        PUT regex_string/$txnid
        POST regex_string

    Args:
        regex_string (str): The regex string to register. Must NOT have a
        trailing $ as this string will be appended to.
        http_server : The http_server to register paths with.
        with_get: True to also register respective GET paths for the PUTs.
    """
    http_server.register_paths(
        "POST", client_patterns(regex_string + "$", v1=True), servlet.on_POST
    )
    http_server.register_paths(
        "PUT",
        client_patterns(regex_string + "/(?P<txn_id>[^/]*)$", v1=True),
        servlet.on_PUT,
    )
    if with_get:
        http_server.register_paths(
            "GET",
            client_patterns(regex_string + "/(?P<txn_id>[^/]*)$", v1=True),
            servlet.on_GET,
        )


def register_servlets(hs, http_server):
    RoomStateEventRestServlet(hs).register(http_server)
    RoomCreateRestServlet(hs).register(http_server)
    RoomMemberListRestServlet(hs).register(http_server)
    JoinedRoomMemberListRestServlet(hs).register(http_server)
    RoomMessageListRestServlet(hs).register(http_server)
    JoinRoomAliasServlet(hs).register(http_server)
    RoomForgetRestServlet(hs).register(http_server)
    RoomMembershipRestServlet(hs).register(http_server)
    RoomSendEventRestServlet(hs).register(http_server)
    PublicRoomListRestServlet(hs).register(http_server)
    RoomStateRestServlet(hs).register(http_server)
    RoomRedactEventRestServlet(hs).register(http_server)
    RoomTypingRestServlet(hs).register(http_server)
    SearchRestServlet(hs).register(http_server)
    JoinedRoomsRestServlet(hs).register(http_server)
    RoomEventServlet(hs).register(http_server)
    RoomEventContextServlet(hs).register(http_server)


def register_deprecated_servlets(hs, http_server):
    RoomInitialSyncRestServlet(hs).register(http_server)
