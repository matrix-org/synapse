import json

from synapse.api.room_versions import RoomVersions
from synapse.federation.transport.client import SendJoinParser

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
