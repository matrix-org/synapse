# -*- coding: utf-8 -*-
# Copyright 2020 Tulir Asokan <tulir@maunium.net>
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

from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.http.servlet import RestServlet, parse_integer
from synapse.logging.opentracing import set_tag

from ._base import client_patterns

logger = logging.getLogger(__name__)


class RoomEventForwardServlet(RestServlet):
    """
    PUT /net.maunium.msc2730/rooms/{room_id}/event/{event_id}/forward/{target_room_id}/{txn_id}
    """

    PATTERNS = client_patterns(
        (
            "/net.maunium.msc2730/rooms/(?P<room_id>[^/]*)/event/(?P<event_id>[^/]*)"
            "/forward/(?P<target_room_id>[^/]*)/(?P<txn_id>.*)"
        ),
        releases=(),  # This is an unstable feature
    )

    _data_key = "net.maunium.msc2730.forwarded"
    _err_not_forwardable = "NET.MAUNIUM.MSC2730_NOT_FORWARDABLE"

    def __init__(self, hs):
        super().__init__()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.event_handler = hs.get_event_handler()
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    async def on_PUT(self, request, room_id, event_id, target_room_id, txn_id):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        try:
            event = await self.event_handler.get_event(
                requester.user, room_id, event_id
            )
        except AuthError:
            event = None
        if not event:
            raise SynapseError(404, "Event not found.", errcode=Codes.NOT_FOUND)

        if event.is_state():
            raise SynapseError(
                401,
                "State events cannot be forwarded.",
                errcode=self._err_not_forwardable,
            )
        elif event.redacts:
            raise SynapseError(
                401,
                "Redaction events cannot be forwarded.",
                errcode=self._err_not_forwardable,
            )
        elif event.internal_metadata.is_redacted():
            raise SynapseError(
                401,
                "Redacted events cannot be forwarded.",
                errcode=self._err_not_forwardable,
            )

        event_id = event.event_id
        event_dict = event.get_dict()

        content = event_dict.pop("content")
        unsigned = event_dict.pop("unsigned", {})
        event_type = event_dict.pop("type")
        has_forward_meta = self._data_key in content
        try:
            is_valid_forward = has_forward_meta and unsigned[self._data_key]["valid"]
        except (KeyError, TypeError):
            is_valid_forward = False

        if has_forward_meta and not is_valid_forward:
            raise SynapseError(
                401,
                "Event contains invalid forward metadata.",
                errcode=self._err_not_forwardable,
            )
        elif not has_forward_meta:
            content[self._data_key] = event_dict
            room_version = await self.store.get_room_version(event.room_id)
            content[self._data_key]["unsigned"] = {
                "room_version": room_version.identifier,
                # TODO add sender profile info here
            }

        forwarded_event_dict = {
            "type": event_type,
            "content": content,
            "room_id": target_room_id,
            "sender": requester.user.to_string(),
            "unsigned": {self._data_key: {"valid": True, "event_id": event_id}},
        }

        if b"ts" in request.args and requester.app_service:
            forwarded_event_dict["origin_server_ts"] = parse_integer(request, "ts", 0)

        (
            forwarded_event,
            _,
        ) = await self.event_creation_handler.create_and_send_nonmember_event(
            requester, forwarded_event_dict, txn_id=txn_id
        )

        set_tag("event_id", forwarded_event.event_id)
        return 200, {"event_id": forwarded_event.event_id}


def register_servlets(hs, http_server):
    RoomEventForwardServlet(hs).register(http_server)
