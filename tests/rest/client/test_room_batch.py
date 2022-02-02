import logging
from typing import List, Tuple
from unittest.mock import Mock, patch

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventContentFields, EventTypes
from synapse.appservice import ApplicationService
from synapse.rest import admin
from synapse.rest.client import login, register, room, room_batch
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest

logger = logging.getLogger(__name__)


def _create_join_state_events_for_batch_send_request(
    virtual_user_ids: List[str],
    insert_time: int,
) -> List[JsonDict]:
    return [
        {
            "type": EventTypes.Member,
            "sender": virtual_user_id,
            "origin_server_ts": insert_time,
            "content": {
                "membership": "join",
                "displayname": "display-name-for-%s" % (virtual_user_id,),
            },
            "state_key": virtual_user_id,
        }
        for virtual_user_id in virtual_user_ids
    ]


def _create_message_events_for_batch_send_request(
    virtual_user_id: str, insert_time: int, count: int
) -> List[JsonDict]:
    return [
        {
            "type": EventTypes.Message,
            "sender": virtual_user_id,
            "origin_server_ts": insert_time,
            "content": {
                "msgtype": "m.text",
                "body": "Historical %d" % (i),
                EventContentFields.MSC2716_HISTORICAL: True,
            },
        }
        for i in range(count)
    ]


class RoomBatchTestCase(unittest.HomeserverTestCase):
    """Test importing batches of historical messages."""

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room_batch.register_servlets,
        room.register_servlets,
        register.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()

        self.appservice = ApplicationService(
            token="i_am_an_app_service",
            hostname="test",
            id="1234",
            namespaces={"users": [{"regex": r"@as_user.*", "exclusive": True}]},
            # Note: this user does not have to match the regex above
            sender="@as_main:test",
        )

        mock_load_appservices = Mock(return_value=[self.appservice])
        with patch(
            "synapse.storage.databases.main.appservice.load_appservices",
            mock_load_appservices,
        ):
            hs = self.setup_test_homeserver(config=config)
        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.clock = clock
        self.storage = hs.get_storage()

        self.virtual_user_id, _ = self.register_appservice_user(
            "as_user_potato", self.appservice.token
        )

    def _create_test_room(self) -> Tuple[str, str, str, str]:
        room_id = self.helper.create_room_as(
            self.appservice.sender, tok=self.appservice.token
        )

        res_a = self.helper.send_event(
            room_id=room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "A",
            },
            tok=self.appservice.token,
        )
        event_id_a = res_a["event_id"]

        res_b = self.helper.send_event(
            room_id=room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "B",
            },
            tok=self.appservice.token,
        )
        event_id_b = res_b["event_id"]

        res_c = self.helper.send_event(
            room_id=room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "C",
            },
            tok=self.appservice.token,
        )
        event_id_c = res_c["event_id"]

        return room_id, event_id_a, event_id_b, event_id_c

    @unittest.override_config({"experimental_features": {"msc2716_enabled": True}})
    def test_same_state_groups_for_whole_historical_batch(self):
        """Make sure that when using the `/batch_send` endpoint to import a
        bunch of historical messages, it re-uses the same `state_group` across
        the whole batch. This is an easy optimization to make sure we're getting
        right because the state for the whole batch is contained in
        `state_events_at_start` and can be shared across everything.
        """

        time_before_room = int(self.clock.time_msec())
        room_id, event_id_a, _, _ = self._create_test_room()

        channel = self.make_request(
            "POST",
            "/_matrix/client/unstable/org.matrix.msc2716/rooms/%s/batch_send?prev_event_id=%s"
            % (room_id, event_id_a),
            content={
                "events": _create_message_events_for_batch_send_request(
                    self.virtual_user_id, time_before_room, 3
                ),
                "state_events_at_start": _create_join_state_events_for_batch_send_request(
                    [self.virtual_user_id], time_before_room
                ),
            },
            access_token=self.appservice.token,
        )
        self.assertEqual(channel.code, 200, channel.result)

        # Get the historical event IDs that we just imported
        historical_event_ids = channel.json_body["event_ids"]
        self.assertEqual(len(historical_event_ids), 3)

        # Fetch the state_groups
        state_group_map = self.get_success(
            self.storage.state.get_state_groups_ids(room_id, historical_event_ids)
        )

        # We expect all of the historical events to be using the same state_group
        # so there should only be a single state_group here!
        self.assertEqual(
            len(state_group_map.keys()),
            1,
            "Expected a single state_group to be returned by saw state_groups=%s"
            % (state_group_map.keys(),),
        )
