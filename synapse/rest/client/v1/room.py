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

""" This module contains REST servlets to do with rooms: /rooms/<paths> """
from twisted.internet import defer

from base import ClientV1RestServlet, client_path_pattern
from synapse.api.errors import SynapseError, Codes
from synapse.streams.config import PaginationConfig
from synapse.api.constants import EventTypes, Membership
from synapse.types import UserID, RoomID, RoomAlias
from synapse.events.utils import serialize_event

import simplejson as json
import logging
import urllib
from synapse.util import stringutils

logger = logging.getLogger(__name__)


class RoomCreateRestServlet(ClientV1RestServlet):
    # No PATTERN; we have custom dispatch rules here

    def register(self, http_server):
        PATTERN = "/createRoom"
        register_txn_path(self, PATTERN, http_server)
        # define CORS for all of /rooms in RoomCreateRestServlet for simplicity
        http_server.register_path("OPTIONS",
                                  client_path_pattern("/rooms(?:/.*)?$"),
                                  self.on_OPTIONS)
        # define CORS for /createRoom[/txnid]
        http_server.register_path("OPTIONS",
                                  client_path_pattern("/createRoom(?:/.*)?$"),
                                  self.on_OPTIONS)

    @defer.inlineCallbacks
    def on_PUT(self, request, txn_id):
        try:
            defer.returnValue(
                self.txns.get_client_transaction(request, txn_id)
            )
        except KeyError:
            pass

        response = yield self.on_POST(request)

        self.txns.store_client_transaction(request, txn_id, response)
        defer.returnValue(response)

    @defer.inlineCallbacks
    def on_POST(self, request):
        auth_user, _ = yield self.auth.get_user_by_req(request)

        room_config = self.get_room_config(request)
        info = yield self.make_room(room_config, auth_user, None)
        room_config.update(info)
        defer.returnValue((200, info))

    @defer.inlineCallbacks
    def make_room(self, room_config, auth_user, room_id):
        handler = self.handlers.room_creation_handler
        info = yield handler.create_room(
            user_id=auth_user.to_string(),
            room_id=room_id,
            config=room_config
        )
        defer.returnValue(info)

    def get_room_config(self, request):
        try:
            user_supplied_config = json.loads(request.content.read())
            if "visibility" not in user_supplied_config:
                # default visibility
                user_supplied_config["visibility"] = "public"
            return user_supplied_config
        except (ValueError, TypeError):
            raise SynapseError(400, "Body must be JSON.",
                               errcode=Codes.BAD_JSON)

    def on_OPTIONS(self, request):
        return (200, {})


# TODO: Needs unit testing for generic events
class RoomStateEventRestServlet(ClientV1RestServlet):
    def register(self, http_server):
        # /room/$roomid/state/$eventtype
        no_state_key = "/rooms/(?P<room_id>[^/]*)/state/(?P<event_type>[^/]*)$"

        # /room/$roomid/state/$eventtype/$statekey
        state_key = ("/rooms/(?P<room_id>[^/]*)/state/"
                     "(?P<event_type>[^/]*)/(?P<state_key>[^/]*)$")

        http_server.register_path("GET",
                                  client_path_pattern(state_key),
                                  self.on_GET)
        http_server.register_path("PUT",
                                  client_path_pattern(state_key),
                                  self.on_PUT)
        http_server.register_path("GET",
                                  client_path_pattern(no_state_key),
                                  self.on_GET_no_state_key)
        http_server.register_path("PUT",
                                  client_path_pattern(no_state_key),
                                  self.on_PUT_no_state_key)

    def on_GET_no_state_key(self, request, room_id, event_type):
        return self.on_GET(request, room_id, event_type, "")

    def on_PUT_no_state_key(self, request, room_id, event_type):
        return self.on_PUT(request, room_id, event_type, "")

    @defer.inlineCallbacks
    def on_GET(self, request, room_id, event_type, state_key):
        user, _ = yield self.auth.get_user_by_req(request)

        msg_handler = self.handlers.message_handler
        data = yield msg_handler.get_room_data(
            user_id=user.to_string(),
            room_id=room_id,
            event_type=event_type,
            state_key=state_key,
        )

        if not data:
            raise SynapseError(
                404, "Event not found.", errcode=Codes.NOT_FOUND
            )
        defer.returnValue((200, data.get_dict()["content"]))

    @defer.inlineCallbacks
    def on_PUT(self, request, room_id, event_type, state_key, txn_id=None):
        user, token_id = yield self.auth.get_user_by_req(request)

        content = _parse_json(request)

        event_dict = {
            "type": event_type,
            "content": content,
            "room_id": room_id,
            "sender": user.to_string(),
        }

        if state_key is not None:
            event_dict["state_key"] = state_key

        msg_handler = self.handlers.message_handler
        yield msg_handler.create_and_send_event(
            event_dict, token_id=token_id, txn_id=txn_id,
        )

        defer.returnValue((200, {}))


# TODO: Needs unit testing for generic events + feedback
class RoomSendEventRestServlet(ClientV1RestServlet):

    def register(self, http_server):
        # /rooms/$roomid/send/$event_type[/$txn_id]
        PATTERN = ("/rooms/(?P<room_id>[^/]*)/send/(?P<event_type>[^/]*)")
        register_txn_path(self, PATTERN, http_server, with_get=True)

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, event_type, txn_id=None):
        user, token_id = yield self.auth.get_user_by_req(request)
        content = _parse_json(request)

        msg_handler = self.handlers.message_handler
        event = yield msg_handler.create_and_send_event(
            {
                "type": event_type,
                "content": content,
                "room_id": room_id,
                "sender": user.to_string(),
            },
            token_id=token_id,
            txn_id=txn_id,
        )

        defer.returnValue((200, {"event_id": event.event_id}))

    def on_GET(self, request, room_id, event_type, txn_id):
        return (200, "Not implemented")

    @defer.inlineCallbacks
    def on_PUT(self, request, room_id, event_type, txn_id):
        try:
            defer.returnValue(
                self.txns.get_client_transaction(request, txn_id)
            )
        except KeyError:
            pass

        response = yield self.on_POST(request, room_id, event_type, txn_id)

        self.txns.store_client_transaction(request, txn_id, response)
        defer.returnValue(response)


# TODO: Needs unit testing for room ID + alias joins
class JoinRoomAliasServlet(ClientV1RestServlet):

    def register(self, http_server):
        # /join/$room_identifier[/$txn_id]
        PATTERN = ("/join/(?P<room_identifier>[^/]*)")
        register_txn_path(self, PATTERN, http_server)

    @defer.inlineCallbacks
    def on_POST(self, request, room_identifier, txn_id=None):
        user, token_id = yield self.auth.get_user_by_req(request)

        # the identifier could be a room alias or a room id. Try one then the
        # other if it fails to parse, without swallowing other valid
        # SynapseErrors.

        identifier = None
        is_room_alias = False
        try:
            identifier = RoomAlias.from_string(room_identifier)
            is_room_alias = True
        except SynapseError:
            identifier = RoomID.from_string(room_identifier)

        # TODO: Support for specifying the home server to join with?

        if is_room_alias:
            handler = self.handlers.room_member_handler
            ret_dict = yield handler.join_room_alias(user, identifier)
            defer.returnValue((200, ret_dict))
        else:  # room id
            msg_handler = self.handlers.message_handler
            yield msg_handler.create_and_send_event(
                {
                    "type": EventTypes.Member,
                    "content": {"membership": Membership.JOIN},
                    "room_id": identifier.to_string(),
                    "sender": user.to_string(),
                    "state_key": user.to_string(),
                },
                token_id=token_id,
                txn_id=txn_id,
            )

            defer.returnValue((200, {"room_id": identifier.to_string()}))

    @defer.inlineCallbacks
    def on_PUT(self, request, room_identifier, txn_id):
        try:
            defer.returnValue(
                self.txns.get_client_transaction(request, txn_id)
            )
        except KeyError:
            pass

        response = yield self.on_POST(request, room_identifier, txn_id)

        self.txns.store_client_transaction(request, txn_id, response)
        defer.returnValue(response)


# TODO: Needs unit testing
class PublicRoomListRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/publicRooms$")

    @defer.inlineCallbacks
    def on_GET(self, request):
        handler = self.handlers.room_list_handler
        data = yield handler.get_public_room_list()
        defer.returnValue((200, data))


# TODO: Needs unit testing
class RoomMemberListRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/rooms/(?P<room_id>[^/]*)/members$")

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        # TODO support Pagination stream API (limit/tokens)
        user, _ = yield self.auth.get_user_by_req(request)
        handler = self.handlers.room_member_handler
        members = yield handler.get_room_members_as_pagination_chunk(
            room_id=room_id,
            user_id=user.to_string())

        for event in members["chunk"]:
            # FIXME: should probably be state_key here, not user_id
            target_user = UserID.from_string(event["user_id"])
            # Presence is an optional cache; don't fail if we can't fetch it
            try:
                presence_handler = self.handlers.presence_handler
                presence_state = yield presence_handler.get_state(
                    target_user=target_user, auth_user=user
                )
                event["content"].update(presence_state)
            except:
                pass

        defer.returnValue((200, members))


# TODO: Needs unit testing
class RoomMessageListRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/rooms/(?P<room_id>[^/]*)/messages$")

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        user, _ = yield self.auth.get_user_by_req(request)
        pagination_config = PaginationConfig.from_request(
            request, default_limit=10,
        )
        with_feedback = "feedback" in request.args
        as_client_event = "raw" not in request.args
        handler = self.handlers.message_handler
        msgs = yield handler.get_messages(
            room_id=room_id,
            user_id=user.to_string(),
            pagin_config=pagination_config,
            feedback=with_feedback,
            as_client_event=as_client_event
        )

        defer.returnValue((200, msgs))


# TODO: Needs unit testing
class RoomStateRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/rooms/(?P<room_id>[^/]*)/state$")

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        user, _ = yield self.auth.get_user_by_req(request)
        handler = self.handlers.message_handler
        # Get all the current state for this room
        events = yield handler.get_state_events(
            room_id=room_id,
            user_id=user.to_string(),
        )
        defer.returnValue((200, events))


# TODO: Needs unit testing
class RoomInitialSyncRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/rooms/(?P<room_id>[^/]*)/initialSync$")

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        user, _ = yield self.auth.get_user_by_req(request)
        pagination_config = PaginationConfig.from_request(request)
        content = yield self.handlers.message_handler.room_initial_sync(
            room_id=room_id,
            user_id=user.to_string(),
            pagin_config=pagination_config,
        )
        defer.returnValue((200, content))


class RoomTriggerBackfill(ClientV1RestServlet):
    PATTERN = client_path_pattern("/rooms/(?P<room_id>[^/]*)/backfill$")

    def __init__(self, hs):
        super(RoomTriggerBackfill, self).__init__(hs)
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        remote_server = urllib.unquote(
            request.args["remote"][0]
        ).decode("UTF-8")

        limit = int(request.args["limit"][0])

        handler = self.handlers.federation_handler
        events = yield handler.backfill(remote_server, room_id, limit)

        time_now = self.clock.time_msec()

        res = [serialize_event(event, time_now) for event in events]
        defer.returnValue((200, res))


# TODO: Needs unit testing
class RoomMembershipRestServlet(ClientV1RestServlet):

    def register(self, http_server):
        # /rooms/$roomid/[invite|join|leave]
        PATTERN = ("/rooms/(?P<room_id>[^/]*)/"
                   "(?P<membership_action>join|invite|leave|ban|kick)")
        register_txn_path(self, PATTERN, http_server)

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, membership_action, txn_id=None):
        user, token_id = yield self.auth.get_user_by_req(request)

        content = _parse_json(request)

        # target user is you unless it is an invite
        state_key = user.to_string()
        if membership_action in ["invite", "ban", "kick"]:
            try:
                state_key = content["user_id"]
            except KeyError:
                if membership_action == "invite" and "id_server" in content:
                    _assert_has_keys(content, {"id_server", "medium", "address"})
                    id_server = content["id_server"]
                    medium = content["medium"]
                    address = content["address"]
                    state_key = yield self._lookup_3pid_user(id_server, medium, address)
                    if not state_key:
                        self._register_3pid_callback_for_invite(
                            id_server, medium, address, room_id, user, token_id
                        )
                        # Mapping was not known, callback has been registered in
                        # case it becomes known in the future.
                        defer.returnValue((200, {}))
                        return
                else:
                    raise SynapseError(400, "Missing user_id key.")
            # make sure it looks like a user ID; it'll throw if it's invalid.
            UserID.from_string(state_key)

            if membership_action == "kick":
                membership_action = "leave"

        msg_handler = self.handlers.message_handler
        yield msg_handler.create_and_send_event(
            {
                "type": EventTypes.Member,
                "content": {"membership": unicode(membership_action)},
                "room_id": room_id,
                "sender": user.to_string(),
                "state_key": state_key,
            },
            token_id=token_id,
            txn_id=txn_id,
        )

        defer.returnValue((200, {}))

    @defer.inlineCallbacks
    def _lookup_3pid_user(self, id_server, medium, address):
        """Looks up a 3pid in the passed identity server.

        Args:
            id_server (str): The server name (including port, if required)
                of the identity server to use.
            medium (str): The type of the third party identifier (e.g. "email").
            address (str): The third party identifier (e.g. "foo@example.com").

        Returns:
            (str) the matrix ID of the 3pid, or None if it is not recognized.
        """
        data = yield self.hs.get_simple_http_client().get_json(
            "http://%s/_matrix/identity/api/v1/lookup" % (id_server,),
            {
                "medium": medium,
                "address": address,
            }
        )
        if "mxid" in data:
            # TODO: Validate the response signature and such
            defer.returnValue(data["mxid"])

    @defer.inlineCallbacks
    def _register_3pid_callback_for_invite(
            self, id_server, medium, address, room_id, inviting_user, token_id):
        """Requests a 3pid server to call back to us if it gets a specific binding.

        Args:
            id_server (str): The 3pid server to contact.
            medium (str): The type of the third party identifier (e.g. "email").
            address (str): The third party identifier (e.g. "foo@example.com").
            room_id (str): The room to which the 3pid is being invited.
            inviting_user (UserID): The user inviting the 3pid to the room.
            token_id (int): The ID of the access token with which inviting_user
                make the invite.

        """
        nonce = stringutils.random_string(36)

        yield self.hs.get_datastore().store_pending_invitation(
            nonce,
            room_id,
            inviting_user.to_string(),
            token_id
        )

        is_url = "https://%s/_matrix/identity/api/v1/register-callback" % (id_server,)
        callback_url = "https://%s/3pid-registered-callback" % (
            self.hs.config.server_name,
        )
        yield self.hs.get_simple_http_client().post_json_get_json(
            is_url,
            {
                "medium": medium,
                "address": address,
                "nonce": nonce,
                "url": callback_url,
            }
        )

    @defer.inlineCallbacks
    def on_PUT(self, request, room_id, membership_action, txn_id):
        try:
            defer.returnValue(
                self.txns.get_client_transaction(request, txn_id)
            )
        except KeyError:
            pass

        response = yield self.on_POST(
            request, room_id, membership_action, txn_id
        )

        self.txns.store_client_transaction(request, txn_id, response)
        defer.returnValue(response)


class ThreePidRegisteredRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/3pid-registered-callback$")

    @defer.inlineCallbacks
    def on_POST(self, request):
        content = _parse_json(request, expected_keys={"nonce", "mxid"})
        nonce = content["nonce"]
        invitee = content["mxid"]
        store = self.hs.get_datastore()
        val = yield store.get_and_delete_pending_invitation_by_nonce(nonce)
        if not val:
            raise SynapseError(404, errcode=Codes.UNRECOGNIZED)

        msg_handler = self.handlers.message_handler
        yield msg_handler.create_and_send_event(
            {
                "type": EventTypes.Member,
                "content": {"membership": unicode("invite")},
                "room_id": val["room_id"],
                "sender": val["inviting_user_id"],
                "state_key": invitee,
            },
            token_id=val["token_id"],
        )
        defer.returnValue((200, {}))


class RoomRedactEventRestServlet(ClientV1RestServlet):
    def register(self, http_server):
        PATTERN = ("/rooms/(?P<room_id>[^/]*)/redact/(?P<event_id>[^/]*)")
        register_txn_path(self, PATTERN, http_server)

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, event_id, txn_id=None):
        user, token_id = yield self.auth.get_user_by_req(request)
        content = _parse_json(request)

        msg_handler = self.handlers.message_handler
        event = yield msg_handler.create_and_send_event(
            {
                "type": EventTypes.Redaction,
                "content": content,
                "room_id": room_id,
                "sender": user.to_string(),
                "redacts": event_id,
            },
            token_id=token_id,
            txn_id=txn_id,
        )

        defer.returnValue((200, {"event_id": event.event_id}))

    @defer.inlineCallbacks
    def on_PUT(self, request, room_id, event_id, txn_id):
        try:
            defer.returnValue(
                self.txns.get_client_transaction(request, txn_id)
            )
        except KeyError:
            pass

        response = yield self.on_POST(request, room_id, event_id, txn_id)

        self.txns.store_client_transaction(request, txn_id, response)
        defer.returnValue(response)


class RoomTypingRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern(
        "/rooms/(?P<room_id>[^/]*)/typing/(?P<user_id>[^/]*)$"
    )

    @defer.inlineCallbacks
    def on_PUT(self, request, room_id, user_id):
        auth_user, _ = yield self.auth.get_user_by_req(request)

        room_id = urllib.unquote(room_id)
        target_user = UserID.from_string(urllib.unquote(user_id))

        content = _parse_json(request)

        typing_handler = self.handlers.typing_notification_handler

        if content["typing"]:
            yield typing_handler.started_typing(
                target_user=target_user,
                auth_user=auth_user,
                room_id=room_id,
                timeout=content.get("timeout", 30000),
            )
        else:
            yield typing_handler.stopped_typing(
                target_user=target_user,
                auth_user=auth_user,
                room_id=room_id,
            )

        defer.returnValue((200, {}))


def _parse_json(request, expected_keys=None):
    try:
        content = json.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.",
                               errcode=Codes.NOT_JSON)
        if expected_keys:
            _assert_has_keys(content, expected_keys)
        return content
    except ValueError:
        raise SynapseError(400, "Content not JSON.", errcode=Codes.NOT_JSON)


def _assert_has_keys(content, expected_keys):
    missing_keys = set(expected_keys) - set(content.keys())
    if missing_keys:
        raise SynapseError(404, "Missing expected keys: %s" % (
            ",".join(missing_keys),
        ))


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
    http_server.register_path(
        "POST",
        client_path_pattern(regex_string + "$"),
        servlet.on_POST
    )
    http_server.register_path(
        "PUT",
        client_path_pattern(regex_string + "/(?P<txn_id>[^/]*)$"),
        servlet.on_PUT
    )
    if with_get:
        http_server.register_path(
            "GET",
            client_path_pattern(regex_string + "/(?P<txn_id>[^/]*)$"),
            servlet.on_GET
        )


def register_servlets(hs, http_server):
    RoomStateEventRestServlet(hs).register(http_server)
    RoomCreateRestServlet(hs).register(http_server)
    RoomMemberListRestServlet(hs).register(http_server)
    RoomMessageListRestServlet(hs).register(http_server)
    JoinRoomAliasServlet(hs).register(http_server)
    RoomTriggerBackfill(hs).register(http_server)
    RoomMembershipRestServlet(hs).register(http_server)
    RoomSendEventRestServlet(hs).register(http_server)
    PublicRoomListRestServlet(hs).register(http_server)
    RoomStateRestServlet(hs).register(http_server)
    RoomInitialSyncRestServlet(hs).register(http_server)
    RoomRedactEventRestServlet(hs).register(http_server)
    RoomTypingRestServlet(hs).register(http_server)
    ThreePidRegisteredRestServlet(hs).register(http_server)
