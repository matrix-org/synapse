# Copyright 2021 The Matrix.org Foundation C.I.C.
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

import json
from unittest.mock import Mock

import ijson.common

from synapse.api.room_versions import RoomVersions
from synapse.federation.transport.client import SendJoinParser
from synapse.util import ExceptionBundle

from tests.unittest import TestCase


class SendJoinParserTestCase(TestCase):
    def test_two_writes(self) -> None:
        """Test that the parser can sensibly deserialise an input given in two slices."""
        parser = SendJoinParser(RoomVersions.V1, True)
        parent_event = {
            "content": {
                "see_room_version_spec": "The event format changes depending on the room version."
            },
            "event_id": "$authparent",
            "room_id": "!somewhere:example.org",
            "type": "m.room.minimal_pdu",
        }
        state = {
            "content": {
                "see_room_version_spec": "The event format changes depending on the room version."
            },
            "event_id": "$DoNotThinkAboutTheEvent",
            "room_id": "!somewhere:example.org",
            "type": "m.room.minimal_pdu",
        }
        response = [
            200,
            {
                "auth_chain": [parent_event],
                "origin": "matrix.org",
                "state": [state],
            },
        ]
        serialised_response = json.dumps(response).encode()

        # Send data to the parser
        parser.write(serialised_response[:100])
        parser.write(serialised_response[100:])

        # Retrieve the parsed SendJoinResponse
        parsed_response = parser.finish()

        # Sanity check the parsing gave us sensible data.
        self.assertEqual(len(parsed_response.auth_events), 1, parsed_response)
        self.assertEqual(len(parsed_response.state), 1, parsed_response)
        self.assertEqual(parsed_response.event_dict, {}, parsed_response)
        self.assertIsNone(parsed_response.event, parsed_response)
        self.assertFalse(parsed_response.partial_state, parsed_response)
        self.assertEqual(parsed_response.servers_in_room, None, parsed_response)

    def test_partial_state(self) -> None:
        """Check that the partial_state flag is correctly parsed"""
        parser = SendJoinParser(RoomVersions.V1, False)
        response = {
            "org.matrix.msc3706.partial_state": True,
        }

        serialised_response = json.dumps(response).encode()

        # Send data to the parser
        parser.write(serialised_response)

        # Retrieve and check the parsed SendJoinResponse
        parsed_response = parser.finish()
        self.assertTrue(parsed_response.partial_state)

    def test_servers_in_room(self) -> None:
        """Check that the servers_in_room field is correctly parsed"""
        parser = SendJoinParser(RoomVersions.V1, False)
        response = {"org.matrix.msc3706.servers_in_room": ["hs1", "hs2"]}

        serialised_response = json.dumps(response).encode()

        # Send data to the parser
        parser.write(serialised_response)

        # Retrieve and check the parsed SendJoinResponse
        parsed_response = parser.finish()
        self.assertEqual(parsed_response.servers_in_room, ["hs1", "hs2"])

    def test_errors_closing_coroutines(self) -> None:
        """Check we close all coroutines, even if closing the first raises an Exception.

        We also check that an Exception of some kind is raised, but we don't make any
        assertions about its attributes or type.
        """
        parser = SendJoinParser(RoomVersions.V1, False)
        response = {"org.matrix.msc3706.servers_in_room": ["hs1", "hs2"]}
        serialisation = json.dumps(response).encode()

        # Mock the coroutines managed by this parser.
        # The first one will error when we try to close it.
        coro_1 = Mock()
        coro_1.close = Mock(side_effect=RuntimeError("Couldn't close coro 1"))

        coro_2 = Mock()

        coro_3 = Mock()
        coro_3.close = Mock(side_effect=RuntimeError("Couldn't close coro 3"))

        original_coros = parser._coros
        parser._coros = [coro_1, coro_2, coro_3]

        # Close the original coroutines. If we don't, when we garbage collect them
        # they will throw, failing the test. (Oddly, this only started in CPython 3.11).
        for coro in original_coros:
            try:
                coro.close()
            except ijson.common.IncompleteJSONError:
                pass

        # Send half of the data to the parser
        parser.write(serialisation[: len(serialisation) // 2])

        # Close the parser. There should be _some_ kind of exception.
        with self.assertRaises(ExceptionBundle):
            parser.finish()

        # In any case, we should have tried to close both coros.
        coro_1.close.assert_called()
        coro_2.close.assert_called()
        coro_3.close.assert_called()
