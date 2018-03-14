# -*- coding: utf-8 -*-
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

import logging
import re

from twisted.internet import defer

from synapse.api.errors import SynapseError, MatrixCodeMessageException
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.types import Requester, UserID
from synapse.util.distributor import user_left_room, user_joined_room

logger = logging.getLogger(__name__)


@defer.inlineCallbacks
def remote_join(client, host, port, requester, remote_room_hosts,
                room_id, user_id, content):
    """Ask the master to do a remote join for the given user to the given room

    Args:
        client (SimpleHttpClient)
        host (str): host of master
        port (int): port on master listening for HTTP replication
        requester (Requester)
        remote_room_hosts (list[str]): Servers to try and join via
        room_id (str)
        user_id (str)
        content (dict): The event content to use for the join event

    Returns:
        Deferred
    """
    uri = "http://%s:%s/_synapse/replication/remote_join" % (host, port)

    payload = {
        "requester": requester.serialize(),
        "remote_room_hosts": remote_room_hosts,
        "room_id": room_id,
        "user_id": user_id,
        "content": content,
    }

    try:
        result = yield client.post_json_get_json(uri, payload)
    except MatrixCodeMessageException as e:
        # We convert to SynapseError as we know that it was a SynapseError
        # on the master process that we should send to the client. (And
        # importantly, not stack traces everywhere)
        raise SynapseError(e.code, e.msg, e.errcode)
    defer.returnValue(result)


@defer.inlineCallbacks
def remote_reject_invite(client, host, port, requester, remote_room_hosts,
                         room_id, user_id):
    """Ask master to reject the invite for the user and room.

    Args:
        client (SimpleHttpClient)
        host (str): host of master
        port (int): port on master listening for HTTP replication
        requester (Requester)
        remote_room_hosts (list[str]): Servers to try and reject via
        room_id (str)
        user_id (str)

    Returns:
        Deferred
    """
    uri = "http://%s:%s/_synapse/replication/remote_reject_invite" % (host, port)

    payload = {
        "requester": requester.serialize(),
        "remote_room_hosts": remote_room_hosts,
        "room_id": room_id,
        "user_id": user_id,
    }

    try:
        result = yield client.post_json_get_json(uri, payload)
    except MatrixCodeMessageException as e:
        # We convert to SynapseError as we know that it was a SynapseError
        # on the master process that we should send to the client. (And
        # importantly, not stack traces everywhere)
        raise SynapseError(e.code, e.msg, e.errcode)
    defer.returnValue(result)


@defer.inlineCallbacks
def get_or_register_3pid_guest(client, host, port, requester,
                               medium, address, inviter_user_id):
    """Ask the master to get/create a guest account for given 3PID.

    Args:
        client (SimpleHttpClient)
        host (str): host of master
        port (int): port on master listening for HTTP replication
        requester (Requester)
        medium (str)
        address (str)
        inviter_user_id (str): The user ID who is trying to invite the
            3PID

    Returns:
        Deferred[(str, str)]: A 2-tuple of `(user_id, access_token)` of the
        3PID guest account.
    """

    uri = "http://%s:%s/_synapse/replication/get_or_register_3pid_guest" % (host, port)

    payload = {
        "requester": requester.serialize(),
        "medium": medium,
        "address": address,
        "inviter_user_id": inviter_user_id,
    }

    try:
        result = yield client.post_json_get_json(uri, payload)
    except MatrixCodeMessageException as e:
        # We convert to SynapseError as we know that it was a SynapseError
        # on the master process that we should send to the client. (And
        # importantly, not stack traces everywhere)
        raise SynapseError(e.code, e.msg, e.errcode)
    defer.returnValue(result)


@defer.inlineCallbacks
def notify_user_membership_change(client, host, port, user_id, room_id, change):
    """Notify master that a user has joined or left the room

    Args:
        client (SimpleHttpClient)
        host (str): host of master
        port (int): port on master listening for HTTP replication.
        user_id (str)
        room_id (str)
        change (str): Either "join" or "left"

    Returns:
        Deferred
    """
    assert change in ("joined", "left")

    uri = "http://%s:%s/_synapse/replication/user_%s_room" % (host, port, change)

    payload = {
        "user_id": user_id,
        "room_id": room_id,
    }

    try:
        result = yield client.post_json_get_json(uri, payload)
    except MatrixCodeMessageException as e:
        # We convert to SynapseError as we know that it was a SynapseError
        # on the master process that we should send to the client. (And
        # importantly, not stack traces everywhere)
        raise SynapseError(e.code, e.msg, e.errcode)
    defer.returnValue(result)


class ReplicationRemoteJoinRestServlet(RestServlet):
    PATTERNS = [re.compile("^/_synapse/replication/remote_join$")]

    def __init__(self, hs):
        super(ReplicationRemoteJoinRestServlet, self).__init__()

        self.federation_handler = hs.get_handlers().federation_handler
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def on_POST(self, request):
        content = parse_json_object_from_request(request)

        remote_room_hosts = content["remote_room_hosts"]
        room_id = content["room_id"]
        user_id = content["user_id"]
        event_content = content["content"]

        requester = Requester.deserialize(self.store, content["requester"])

        if requester.user:
            request.authenticated_entity = requester.user.to_string()

        logger.info(
            "remote_join: %s into room: %s",
            user_id, room_id,
        )

        yield self.federation_handler.do_invite_join(
            remote_room_hosts,
            room_id,
            user_id,
            event_content,
        )

        defer.returnValue((200, {}))


class ReplicationRemoteRejectInviteRestServlet(RestServlet):
    PATTERNS = [re.compile("^/_synapse/replication/remote_reject_invite$")]

    def __init__(self, hs):
        super(ReplicationRemoteRejectInviteRestServlet, self).__init__()

        self.federation_handler = hs.get_handlers().federation_handler
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def on_POST(self, request):
        content = parse_json_object_from_request(request)

        remote_room_hosts = content["remote_room_hosts"]
        room_id = content["room_id"]
        user_id = content["user_id"]

        requester = Requester.deserialize(self.store, content["requester"])

        if requester.user:
            request.authenticated_entity = requester.user.to_string()

        logger.info(
            "remote_reject_invite: %s out of room: %s",
            user_id, room_id,
        )

        try:
            event = yield self.federation_handler.do_remotely_reject_invite(
                remote_room_hosts,
                room_id,
                user_id,
            )
            ret = event.get_pdu_json()
        except Exception as e:
            # if we were unable to reject the exception, just mark
            # it as rejected on our end and plough ahead.
            #
            # The 'except' clause is very broad, but we need to
            # capture everything from DNS failures upwards
            #
            logger.warn("Failed to reject invite: %s", e)

            yield self.store.locally_reject_invite(
                user_id, room_id
            )
            ret = {}

        defer.returnValue((200, ret))


class ReplicationRegister3PIDGuestRestServlet(RestServlet):
    PATTERNS = [re.compile("^/_synapse/replication/get_or_register_3pid_guest$")]

    def __init__(self, hs):
        super(ReplicationRegister3PIDGuestRestServlet, self).__init__()

        self.registeration_handler = hs.get_handlers().registration_handler
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def on_POST(self, request):
        content = parse_json_object_from_request(request)

        medium = content["medium"]
        address = content["address"]
        inviter_user_id = content["inviter_user_id"]

        requester = Requester.deserialize(self.store, content["requester"])

        if requester.user:
            request.authenticated_entity = requester.user.to_string()

        logger.info("get_or_register_3pid_guest: %r", content)

        ret = yield self.registeration_handler.get_or_register_3pid_guest(
            medium, address, inviter_user_id,
        )

        defer.returnValue((200, ret))


class ReplicationUserJoinedLeftRoomRestServlet(RestServlet):
    PATTERNS = [re.compile("^/_synapse/replication/user_(?P<change>joined|left)_room$")]

    def __init__(self, hs):
        super(ReplicationUserJoinedLeftRoomRestServlet, self).__init__()

        self.registeration_handler = hs.get_handlers().registration_handler
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.distributor = hs.get_distributor()

    def on_POST(self, request, change):
        content = parse_json_object_from_request(request)

        user_id = content["user_id"]
        room_id = content["room_id"]

        logger.info("user membership change: %s in %s", user_id, room_id)

        user = UserID.from_string(user_id)

        if change == "joined":
            user_joined_room(self.distributor, user, room_id)
        elif change == "left":
            user_left_room(self.distributor, user, room_id)
        else:
            raise Exception("Unrecognized change: %r", change)

        return (200, {})


def register_servlets(hs, http_server):
    ReplicationRemoteJoinRestServlet(hs).register(http_server)
    ReplicationRemoteRejectInviteRestServlet(hs).register(http_server)
    ReplicationRegister3PIDGuestRestServlet(hs).register(http_server)
    ReplicationUserJoinedLeftRoomRestServlet(hs).register(http_server)
