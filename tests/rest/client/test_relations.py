# Copyright 2019 New Vector Ltd
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

import itertools
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventTypes, RelationTypes
from synapse.rest import admin
from synapse.rest.client import login, register, relations, room, sync
from synapse.server import HomeServer
from synapse.storage.relations import RelationPaginationToken
from synapse.types import JsonDict, StreamToken
from synapse.util import Clock

from tests import unittest
from tests.server import FakeChannel
from tests.test_utils import make_awaitable
from tests.test_utils.event_injection import inject_event


class BaseRelationsTestCase(unittest.HomeserverTestCase):
    servlets = [
        relations.register_servlets,
        room.register_servlets,
        sync.register_servlets,
        login.register_servlets,
        register.register_servlets,
        admin.register_servlets_for_client_rest_resource,
    ]
    hijack_auth = False

    def default_config(self) -> Dict[str, Any]:
        # We need to enable msc1849 support for aggregations
        config = super().default_config()

        # We enable frozen dicts as relations/edits change event contents, so we
        # want to test that we don't modify the events in the caches.
        config["use_frozen_dicts"] = True

        return config

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.user_id, self.user_token = self._create_user("alice")
        self.user2_id, self.user2_token = self._create_user("bob")

        self.room = self.helper.create_room_as(self.user_id, tok=self.user_token)
        self.helper.join(self.room, user=self.user2_id, tok=self.user2_token)
        res = self.helper.send(self.room, body="Hi!", tok=self.user_token)
        self.parent_id = res["event_id"]

    def _create_user(self, localpart: str) -> Tuple[str, str]:
        user_id = self.register_user(localpart, "abc123")
        access_token = self.login(localpart, "abc123")

        return user_id, access_token

    def _send_relation(
        self,
        relation_type: str,
        event_type: str,
        key: Optional[str] = None,
        content: Optional[dict] = None,
        access_token: Optional[str] = None,
        parent_id: Optional[str] = None,
    ) -> FakeChannel:
        """Helper function to send a relation pointing at `self.parent_id`

        Args:
            relation_type: One of `RelationTypes`
            event_type: The type of the event to create
            key: The aggregation key used for m.annotation relation type.
            content: The content of the created event. Will be modified to configure
                the m.relates_to key based on the other provided parameters.
            access_token: The access token used to send the relation, defaults
                to `self.user_token`
            parent_id: The event_id this relation relates to. If None, then self.parent_id

        Returns:
            FakeChannel
        """
        if not access_token:
            access_token = self.user_token

        original_id = parent_id if parent_id else self.parent_id

        if content is None:
            content = {}
        content["m.relates_to"] = {
            "event_id": original_id,
            "rel_type": relation_type,
        }
        if key is not None:
            content["m.relates_to"]["key"] = key

        channel = self.make_request(
            "POST",
            f"/_matrix/client/v3/rooms/{self.room}/send/{event_type}",
            content,
            access_token=access_token,
        )
        return channel


class RelationsTestCase(BaseRelationsTestCase):
    def test_send_relation(self) -> None:
        """Tests that sending a relation works."""

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="👍")
        self.assertEqual(200, channel.code, channel.json_body)

        event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{event_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        self.assert_dict(
            {
                "type": "m.reaction",
                "sender": self.user_id,
                "content": {
                    "m.relates_to": {
                        "event_id": self.parent_id,
                        "key": "👍",
                        "rel_type": RelationTypes.ANNOTATION,
                    }
                },
            },
            channel.json_body,
        )

    def test_deny_invalid_event(self) -> None:
        """Test that we deny relations on non-existant events"""
        channel = self._send_relation(
            RelationTypes.ANNOTATION,
            EventTypes.Message,
            parent_id="foo",
            content={"body": "foo", "msgtype": "m.text"},
        )
        self.assertEqual(400, channel.code, channel.json_body)

        # Unless that event is referenced from another event!
        self.get_success(
            self.hs.get_datastores().main.db_pool.simple_insert(
                table="event_relations",
                values={
                    "event_id": "bar",
                    "relates_to_id": "foo",
                    "relation_type": RelationTypes.THREAD,
                },
                desc="test_deny_invalid_event",
            )
        )
        channel = self._send_relation(
            RelationTypes.THREAD,
            EventTypes.Message,
            parent_id="foo",
            content={"body": "foo", "msgtype": "m.text"},
        )
        self.assertEqual(200, channel.code, channel.json_body)

    def test_deny_invalid_room(self) -> None:
        """Test that we deny relations on non-existant events"""
        # Create another room and send a message in it.
        room2 = self.helper.create_room_as(self.user_id, tok=self.user_token)
        res = self.helper.send(room2, body="Hi!", tok=self.user_token)
        parent_id = res["event_id"]

        # Attempt to send an annotation to that event.
        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", parent_id=parent_id, key="A"
        )
        self.assertEqual(400, channel.code, channel.json_body)

    def test_deny_double_react(self) -> None:
        """Test that we deny relations on membership events"""
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="a")
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEqual(400, channel.code, channel.json_body)

    def test_deny_forked_thread(self) -> None:
        """It is invalid to start a thread off a thread."""
        channel = self._send_relation(
            RelationTypes.THREAD,
            "m.room.message",
            content={"msgtype": "m.text", "body": "foo"},
            parent_id=self.parent_id,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        parent_id = channel.json_body["event_id"]

        channel = self._send_relation(
            RelationTypes.THREAD,
            "m.room.message",
            content={"msgtype": "m.text", "body": "foo"},
            parent_id=parent_id,
        )
        self.assertEqual(400, channel.code, channel.json_body)

    def test_basic_paginate_relations(self) -> None:
        """Tests that calling pagination API correctly the latest relations."""
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEqual(200, channel.code, channel.json_body)
        first_annotation_id = channel.json_body["event_id"]

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "b")
        self.assertEqual(200, channel.code, channel.json_body)
        second_annotation_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/relations/{self.parent_id}?limit=1",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # We expect to get back a single pagination result, which is the latest
        # full relation event we sent above.
        self.assertEqual(len(channel.json_body["chunk"]), 1, channel.json_body)
        self.assert_dict(
            {
                "event_id": second_annotation_id,
                "sender": self.user_id,
                "type": "m.reaction",
            },
            channel.json_body["chunk"][0],
        )

        # We also expect to get the original event (the id of which is self.parent_id)
        self.assertEqual(
            channel.json_body["original_event"]["event_id"], self.parent_id
        )

        # Make sure next_batch has something in it that looks like it could be a
        # valid token.
        self.assertIsInstance(
            channel.json_body.get("next_batch"), str, channel.json_body
        )

        # Request the relations again, but with a different direction.
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/relations"
            f"/{self.parent_id}?limit=1&org.matrix.msc3715.dir=f",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # We expect to get back a single pagination result, which is the earliest
        # full relation event we sent above.
        self.assertEqual(len(channel.json_body["chunk"]), 1, channel.json_body)
        self.assert_dict(
            {
                "event_id": first_annotation_id,
                "sender": self.user_id,
                "type": "m.reaction",
            },
            channel.json_body["chunk"][0],
        )

    def _stream_token_to_relation_token(self, token: str) -> str:
        """Convert a StreamToken into a legacy token (RelationPaginationToken)."""
        room_key = self.get_success(StreamToken.from_string(self.store, token)).room_key
        return self.get_success(
            RelationPaginationToken(
                topological=room_key.topological, stream=room_key.stream
            ).to_string(self.store)
        )

    def test_repeated_paginate_relations(self) -> None:
        """Test that if we paginate using a limit and tokens then we get the
        expected events.
        """

        expected_event_ids = []
        for idx in range(10):
            channel = self._send_relation(
                RelationTypes.ANNOTATION, "m.reaction", chr(ord("a") + idx)
            )
            self.assertEqual(200, channel.code, channel.json_body)
            expected_event_ids.append(channel.json_body["event_id"])

        prev_token = ""
        found_event_ids: List[str] = []
        for _ in range(20):
            from_token = ""
            if prev_token:
                from_token = "&from=" + prev_token

            channel = self.make_request(
                "GET",
                f"/_matrix/client/unstable/rooms/{self.room}/relations/{self.parent_id}?limit=1{from_token}",
                access_token=self.user_token,
            )
            self.assertEqual(200, channel.code, channel.json_body)

            found_event_ids.extend(e["event_id"] for e in channel.json_body["chunk"])
            next_batch = channel.json_body.get("next_batch")

            self.assertNotEqual(prev_token, next_batch)
            prev_token = next_batch

            if not prev_token:
                break

        # We paginated backwards, so reverse
        found_event_ids.reverse()
        self.assertEqual(found_event_ids, expected_event_ids)

        # Reset and try again, but convert the tokens to the legacy format.
        prev_token = ""
        found_event_ids = []
        for _ in range(20):
            from_token = ""
            if prev_token:
                from_token = "&from=" + self._stream_token_to_relation_token(prev_token)

            channel = self.make_request(
                "GET",
                f"/_matrix/client/unstable/rooms/{self.room}/relations/{self.parent_id}?limit=1{from_token}",
                access_token=self.user_token,
            )
            self.assertEqual(200, channel.code, channel.json_body)

            found_event_ids.extend(e["event_id"] for e in channel.json_body["chunk"])
            next_batch = channel.json_body.get("next_batch")

            self.assertNotEqual(prev_token, next_batch)
            prev_token = next_batch

            if not prev_token:
                break

        # We paginated backwards, so reverse
        found_event_ids.reverse()
        self.assertEqual(found_event_ids, expected_event_ids)

    def test_pagination_from_sync_and_messages(self) -> None:
        """Pagination tokens from /sync and /messages can be used to paginate /relations."""
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "A")
        self.assertEqual(200, channel.code, channel.json_body)
        annotation_id = channel.json_body["event_id"]
        # Send an event after the relation events.
        self.helper.send(self.room, body="Latest event", tok=self.user_token)

        # Request /sync, limiting it such that only the latest event is returned
        # (and not the relation).
        filter = urllib.parse.quote_plus(b'{"room": {"timeline": {"limit": 1}}}')
        channel = self.make_request(
            "GET", f"/sync?filter={filter}", access_token=self.user_token
        )
        self.assertEqual(200, channel.code, channel.json_body)
        room_timeline = channel.json_body["rooms"]["join"][self.room]["timeline"]
        sync_prev_batch = room_timeline["prev_batch"]
        self.assertIsNotNone(sync_prev_batch)
        # Ensure the relation event is not in the batch returned from /sync.
        self.assertNotIn(
            annotation_id, [ev["event_id"] for ev in room_timeline["events"]]
        )

        # Request /messages, limiting it such that only the latest event is
        # returned (and not the relation).
        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/messages?dir=b&limit=1",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        messages_end = channel.json_body["end"]
        self.assertIsNotNone(messages_end)
        # Ensure the relation event is not in the chunk returned from /messages.
        self.assertNotIn(
            annotation_id, [ev["event_id"] for ev in channel.json_body["chunk"]]
        )

        # Request /relations with the pagination tokens received from both the
        # /sync and /messages responses above, in turn.
        #
        # This is a tiny bit silly since the client wouldn't know the parent ID
        # from the requests above; consider the parent ID to be known from a
        # previous /sync.
        for from_token in (sync_prev_batch, messages_end):
            channel = self.make_request(
                "GET",
                f"/_matrix/client/unstable/rooms/{self.room}/relations/{self.parent_id}?from={from_token}",
                access_token=self.user_token,
            )
            self.assertEqual(200, channel.code, channel.json_body)

            # The relation should be in the returned chunk.
            self.assertIn(
                annotation_id, [ev["event_id"] for ev in channel.json_body["chunk"]]
            )

    def test_aggregation_pagination_groups(self) -> None:
        """Test that we can paginate annotation groups correctly."""

        # We need to create ten separate users to send each reaction.
        access_tokens = [self.user_token, self.user2_token]
        idx = 0
        while len(access_tokens) < 10:
            user_id, token = self._create_user("test" + str(idx))
            idx += 1

            self.helper.join(self.room, user=user_id, tok=token)
            access_tokens.append(token)

        idx = 0
        sent_groups = {"👍": 10, "a": 7, "b": 5, "c": 3, "d": 2, "e": 1}
        for key in itertools.chain.from_iterable(
            itertools.repeat(key, num) for key, num in sent_groups.items()
        ):
            channel = self._send_relation(
                RelationTypes.ANNOTATION,
                "m.reaction",
                key=key,
                access_token=access_tokens[idx],
            )
            self.assertEqual(200, channel.code, channel.json_body)

            idx += 1
            idx %= len(access_tokens)

        prev_token: Optional[str] = None
        found_groups: Dict[str, int] = {}
        for _ in range(20):
            from_token = ""
            if prev_token:
                from_token = "&from=" + prev_token

            channel = self.make_request(
                "GET",
                f"/_matrix/client/unstable/rooms/{self.room}/aggregations/{self.parent_id}?limit=1{from_token}",
                access_token=self.user_token,
            )
            self.assertEqual(200, channel.code, channel.json_body)

            self.assertEqual(len(channel.json_body["chunk"]), 1, channel.json_body)

            for groups in channel.json_body["chunk"]:
                # We only expect reactions
                self.assertEqual(groups["type"], "m.reaction", channel.json_body)

                # We should only see each key once
                self.assertNotIn(groups["key"], found_groups, channel.json_body)

                found_groups[groups["key"]] = groups["count"]

            next_batch = channel.json_body.get("next_batch")

            self.assertNotEqual(prev_token, next_batch)
            prev_token = next_batch

            if not prev_token:
                break

        self.assertEqual(sent_groups, found_groups)

    def test_aggregation_pagination_within_group(self) -> None:
        """Test that we can paginate within an annotation group."""

        # We need to create ten separate users to send each reaction.
        access_tokens = [self.user_token, self.user2_token]
        idx = 0
        while len(access_tokens) < 10:
            user_id, token = self._create_user("test" + str(idx))
            idx += 1

            self.helper.join(self.room, user=user_id, tok=token)
            access_tokens.append(token)

        idx = 0
        expected_event_ids = []
        for _ in range(10):
            channel = self._send_relation(
                RelationTypes.ANNOTATION,
                "m.reaction",
                key="👍",
                access_token=access_tokens[idx],
            )
            self.assertEqual(200, channel.code, channel.json_body)
            expected_event_ids.append(channel.json_body["event_id"])

            idx += 1

        # Also send a different type of reaction so that we test we don't see it
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="a")
        self.assertEqual(200, channel.code, channel.json_body)

        prev_token = ""
        found_event_ids: List[str] = []
        encoded_key = urllib.parse.quote_plus("👍".encode())
        for _ in range(20):
            from_token = ""
            if prev_token:
                from_token = "&from=" + prev_token

            channel = self.make_request(
                "GET",
                f"/_matrix/client/unstable/rooms/{self.room}"
                f"/aggregations/{self.parent_id}/{RelationTypes.ANNOTATION}"
                f"/m.reaction/{encoded_key}?limit=1{from_token}",
                access_token=self.user_token,
            )
            self.assertEqual(200, channel.code, channel.json_body)

            self.assertEqual(len(channel.json_body["chunk"]), 1, channel.json_body)

            found_event_ids.extend(e["event_id"] for e in channel.json_body["chunk"])

            next_batch = channel.json_body.get("next_batch")

            self.assertNotEqual(prev_token, next_batch)
            prev_token = next_batch

            if not prev_token:
                break

        # We paginated backwards, so reverse
        found_event_ids.reverse()
        self.assertEqual(found_event_ids, expected_event_ids)

        # Reset and try again, but convert the tokens to the legacy format.
        prev_token = ""
        found_event_ids = []
        for _ in range(20):
            from_token = ""
            if prev_token:
                from_token = "&from=" + self._stream_token_to_relation_token(prev_token)

            channel = self.make_request(
                "GET",
                f"/_matrix/client/unstable/rooms/{self.room}"
                f"/aggregations/{self.parent_id}/{RelationTypes.ANNOTATION}"
                f"/m.reaction/{encoded_key}?limit=1{from_token}",
                access_token=self.user_token,
            )
            self.assertEqual(200, channel.code, channel.json_body)

            self.assertEqual(len(channel.json_body["chunk"]), 1, channel.json_body)

            found_event_ids.extend(e["event_id"] for e in channel.json_body["chunk"])

            next_batch = channel.json_body.get("next_batch")

            self.assertNotEqual(prev_token, next_batch)
            prev_token = next_batch

            if not prev_token:
                break

        # We paginated backwards, so reverse
        found_event_ids.reverse()
        self.assertEqual(found_event_ids, expected_event_ids)

    def test_aggregation(self) -> None:
        """Test that annotations get correctly aggregated."""

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", "a", access_token=self.user2_token
        )
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "b")
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/aggregations/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        self.assertEqual(
            channel.json_body,
            {
                "chunk": [
                    {"type": "m.reaction", "key": "a", "count": 2},
                    {"type": "m.reaction", "key": "b", "count": 1},
                ]
            },
        )

    def test_aggregation_must_be_annotation(self) -> None:
        """Test that aggregations must be annotations."""

        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/aggregations"
            f"/{self.parent_id}/{RelationTypes.REPLACE}?limit=1",
            access_token=self.user_token,
        )
        self.assertEqual(400, channel.code, channel.json_body)

    @unittest.override_config(
        {"experimental_features": {"msc3440_enabled": True, "msc3666_enabled": True}}
    )
    def test_bundled_aggregations(self) -> None:
        """
        Test that annotations, references, and threads get correctly bundled.

        Note that this doesn't test against /relations since only thread relations
        get bundled via that API. See test_aggregation_get_event_for_thread.

        See test_edit for a similar test for edits.
        """
        # Setup by sending a variety of relations.
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", "a", access_token=self.user2_token
        )
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "b")
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.REFERENCE, "m.room.test")
        self.assertEqual(200, channel.code, channel.json_body)
        reply_1 = channel.json_body["event_id"]

        channel = self._send_relation(RelationTypes.REFERENCE, "m.room.test")
        self.assertEqual(200, channel.code, channel.json_body)
        reply_2 = channel.json_body["event_id"]

        channel = self._send_relation(RelationTypes.THREAD, "m.room.test")
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.THREAD, "m.room.test")
        self.assertEqual(200, channel.code, channel.json_body)
        thread_2 = channel.json_body["event_id"]

        def assert_bundle(event_json: JsonDict) -> None:
            """Assert the expected values of the bundled aggregations."""
            relations_dict = event_json["unsigned"].get("m.relations")

            # Ensure the fields are as expected.
            self.assertCountEqual(
                relations_dict.keys(),
                (
                    RelationTypes.ANNOTATION,
                    RelationTypes.REFERENCE,
                    RelationTypes.THREAD,
                ),
            )

            # Check the values of each field.
            self.assertEqual(
                {
                    "chunk": [
                        {"type": "m.reaction", "key": "a", "count": 2},
                        {"type": "m.reaction", "key": "b", "count": 1},
                    ]
                },
                relations_dict[RelationTypes.ANNOTATION],
            )

            self.assertEqual(
                {"chunk": [{"event_id": reply_1}, {"event_id": reply_2}]},
                relations_dict[RelationTypes.REFERENCE],
            )

            self.assertEqual(
                2,
                relations_dict[RelationTypes.THREAD].get("count"),
            )
            self.assertTrue(
                relations_dict[RelationTypes.THREAD].get("current_user_participated")
            )
            # The latest thread event has some fields that don't matter.
            self.assert_dict(
                {
                    "content": {
                        "m.relates_to": {
                            "event_id": self.parent_id,
                            "rel_type": RelationTypes.THREAD,
                        }
                    },
                    "event_id": thread_2,
                    "room_id": self.room,
                    "sender": self.user_id,
                    "type": "m.room.test",
                    "user_id": self.user_id,
                },
                relations_dict[RelationTypes.THREAD].get("latest_event"),
            )

        # Request the event directly.
        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        assert_bundle(channel.json_body)

        # Request the room messages.
        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/messages?dir=b",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        assert_bundle(self._find_event_in_chunk(channel.json_body["chunk"]))

        # Request the room context.
        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/context/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        assert_bundle(channel.json_body["event"])

        # Request sync.
        channel = self.make_request("GET", "/sync", access_token=self.user_token)
        self.assertEqual(200, channel.code, channel.json_body)
        room_timeline = channel.json_body["rooms"]["join"][self.room]["timeline"]
        self.assertTrue(room_timeline["limited"])
        assert_bundle(self._find_event_in_chunk(room_timeline["events"]))

        # Request search.
        channel = self.make_request(
            "POST",
            "/search",
            # Search term matches the parent message.
            content={"search_categories": {"room_events": {"search_term": "Hi"}}},
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        chunk = [
            result["result"]
            for result in channel.json_body["search_categories"]["room_events"][
                "results"
            ]
        ]
        assert_bundle(self._find_event_in_chunk(chunk))

    def test_aggregation_get_event_for_annotation(self) -> None:
        """Test that annotations do not get bundled aggregations included
        when directly requested.
        """
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEqual(200, channel.code, channel.json_body)
        annotation_id = channel.json_body["event_id"]

        # Annotate the annotation.
        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", "a", parent_id=annotation_id
        )
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{annotation_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertIsNone(channel.json_body["unsigned"].get("m.relations"))

    def test_aggregation_get_event_for_thread(self) -> None:
        """Test that threads get bundled aggregations included when directly requested."""
        channel = self._send_relation(RelationTypes.THREAD, "m.room.test")
        self.assertEqual(200, channel.code, channel.json_body)
        thread_id = channel.json_body["event_id"]

        # Annotate the annotation.
        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", "a", parent_id=thread_id
        )
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{thread_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertEqual(
            channel.json_body["unsigned"].get("m.relations"),
            {
                RelationTypes.ANNOTATION: {
                    "chunk": [{"count": 1, "key": "a", "type": "m.reaction"}]
                },
            },
        )

        # It should also be included when the entire thread is requested.
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/relations/{self.parent_id}?limit=1",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertEqual(len(channel.json_body["chunk"]), 1)

        thread_message = channel.json_body["chunk"][0]
        self.assertEqual(
            thread_message["unsigned"].get("m.relations"),
            {
                RelationTypes.ANNOTATION: {
                    "chunk": [{"count": 1, "key": "a", "type": "m.reaction"}]
                },
            },
        )

    @unittest.override_config({"experimental_features": {"msc3440_enabled": True}})
    def test_ignore_invalid_room(self) -> None:
        """Test that we ignore invalid relations over federation."""
        # Create another room and send a message in it.
        room2 = self.helper.create_room_as(self.user_id, tok=self.user_token)
        res = self.helper.send(room2, body="Hi!", tok=self.user_token)
        parent_id = res["event_id"]

        # Disable the validation to pretend this came over federation.
        with patch(
            "synapse.handlers.message.EventCreationHandler._validate_event_relation",
            new=lambda self, event: make_awaitable(None),
        ):
            # Generate a various relations from a different room.
            self.get_success(
                inject_event(
                    self.hs,
                    room_id=self.room,
                    type="m.reaction",
                    sender=self.user_id,
                    content={
                        "m.relates_to": {
                            "rel_type": RelationTypes.ANNOTATION,
                            "event_id": parent_id,
                            "key": "A",
                        }
                    },
                )
            )

            self.get_success(
                inject_event(
                    self.hs,
                    room_id=self.room,
                    type="m.room.message",
                    sender=self.user_id,
                    content={
                        "body": "foo",
                        "msgtype": "m.text",
                        "m.relates_to": {
                            "rel_type": RelationTypes.REFERENCE,
                            "event_id": parent_id,
                        },
                    },
                )
            )

            self.get_success(
                inject_event(
                    self.hs,
                    room_id=self.room,
                    type="m.room.message",
                    sender=self.user_id,
                    content={
                        "body": "foo",
                        "msgtype": "m.text",
                        "m.relates_to": {
                            "rel_type": RelationTypes.THREAD,
                            "event_id": parent_id,
                        },
                    },
                )
            )

            self.get_success(
                inject_event(
                    self.hs,
                    room_id=self.room,
                    type="m.room.message",
                    sender=self.user_id,
                    content={
                        "body": "foo",
                        "msgtype": "m.text",
                        "new_content": {
                            "body": "new content",
                            "msgtype": "m.text",
                        },
                        "m.relates_to": {
                            "rel_type": RelationTypes.REPLACE,
                            "event_id": parent_id,
                        },
                    },
                )
            )

        # They should be ignored when fetching relations.
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{room2}/relations/{parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertEqual(channel.json_body["chunk"], [])

        # And when fetching aggregations.
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{room2}/aggregations/{parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertEqual(channel.json_body["chunk"], [])

        # And for bundled aggregations.
        channel = self.make_request(
            "GET",
            f"/rooms/{room2}/event/{parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertNotIn("m.relations", channel.json_body["unsigned"])

    @unittest.override_config({"experimental_features": {"msc3666_enabled": True}})
    def test_edit(self) -> None:
        """Test that a simple edit works."""

        new_body = {"msgtype": "m.text", "body": "I've been edited!"}
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            content={"msgtype": "m.text", "body": "foo", "m.new_content": new_body},
        )
        self.assertEqual(200, channel.code, channel.json_body)

        edit_event_id = channel.json_body["event_id"]

        def assert_bundle(event_json: JsonDict) -> None:
            """Assert the expected values of the bundled aggregations."""
            relations_dict = event_json["unsigned"].get("m.relations")
            self.assertIn(RelationTypes.REPLACE, relations_dict)

            m_replace_dict = relations_dict[RelationTypes.REPLACE]
            for key in ["event_id", "sender", "origin_server_ts"]:
                self.assertIn(key, m_replace_dict)

            self.assert_dict(
                {"event_id": edit_event_id, "sender": self.user_id}, m_replace_dict
            )

        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertEqual(channel.json_body["content"], new_body)
        assert_bundle(channel.json_body)

        # Request the room messages.
        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/messages?dir=b",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        assert_bundle(self._find_event_in_chunk(channel.json_body["chunk"]))

        # Request the room context.
        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/context/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        assert_bundle(channel.json_body["event"])

        # Request sync, but limit the timeline so it becomes limited (and includes
        # bundled aggregations).
        filter = urllib.parse.quote_plus(b'{"room": {"timeline": {"limit": 2}}}')
        channel = self.make_request(
            "GET", f"/sync?filter={filter}", access_token=self.user_token
        )
        self.assertEqual(200, channel.code, channel.json_body)
        room_timeline = channel.json_body["rooms"]["join"][self.room]["timeline"]
        self.assertTrue(room_timeline["limited"])
        assert_bundle(self._find_event_in_chunk(room_timeline["events"]))

        # Request search.
        channel = self.make_request(
            "POST",
            "/search",
            # Search term matches the parent message.
            content={"search_categories": {"room_events": {"search_term": "Hi"}}},
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        chunk = [
            result["result"]
            for result in channel.json_body["search_categories"]["room_events"][
                "results"
            ]
        ]
        assert_bundle(self._find_event_in_chunk(chunk))

    def test_multi_edit(self) -> None:
        """Test that multiple edits, including attempts by people who
        shouldn't be allowed, are correctly handled.
        """

        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            content={
                "msgtype": "m.text",
                "body": "Wibble",
                "m.new_content": {"msgtype": "m.text", "body": "First edit"},
            },
        )
        self.assertEqual(200, channel.code, channel.json_body)

        new_body = {"msgtype": "m.text", "body": "I've been edited!"}
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            content={"msgtype": "m.text", "body": "foo", "m.new_content": new_body},
        )
        self.assertEqual(200, channel.code, channel.json_body)

        edit_event_id = channel.json_body["event_id"]

        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message.WRONG_TYPE",
            content={
                "msgtype": "m.text",
                "body": "Wibble",
                "m.new_content": {"msgtype": "m.text", "body": "Edit, but wrong type"},
            },
        )
        self.assertEqual(200, channel.code, channel.json_body)

        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        self.assertEqual(channel.json_body["content"], new_body)

        relations_dict = channel.json_body["unsigned"].get("m.relations")
        self.assertIn(RelationTypes.REPLACE, relations_dict)

        m_replace_dict = relations_dict[RelationTypes.REPLACE]
        for key in ["event_id", "sender", "origin_server_ts"]:
            self.assertIn(key, m_replace_dict)

        self.assert_dict(
            {"event_id": edit_event_id, "sender": self.user_id}, m_replace_dict
        )

    def test_edit_reply(self) -> None:
        """Test that editing a reply works."""

        # Create a reply to edit.
        channel = self._send_relation(
            RelationTypes.REFERENCE,
            "m.room.message",
            content={"msgtype": "m.text", "body": "A reply!"},
        )
        self.assertEqual(200, channel.code, channel.json_body)
        reply = channel.json_body["event_id"]

        new_body = {"msgtype": "m.text", "body": "I've been edited!"}
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            content={"msgtype": "m.text", "body": "foo", "m.new_content": new_body},
            parent_id=reply,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        edit_event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{reply}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # We expect to see the new body in the dict, as well as the reference
        # metadata sill intact.
        self.assertDictContainsSubset(new_body, channel.json_body["content"])
        self.assertDictContainsSubset(
            {
                "m.relates_to": {
                    "event_id": self.parent_id,
                    "rel_type": "m.reference",
                }
            },
            channel.json_body["content"],
        )

        # We expect that the edit relation appears in the unsigned relations
        # section.
        relations_dict = channel.json_body["unsigned"].get("m.relations")
        self.assertIn(RelationTypes.REPLACE, relations_dict)

        m_replace_dict = relations_dict[RelationTypes.REPLACE]
        for key in ["event_id", "sender", "origin_server_ts"]:
            self.assertIn(key, m_replace_dict)

        self.assert_dict(
            {"event_id": edit_event_id, "sender": self.user_id}, m_replace_dict
        )

    @unittest.override_config({"experimental_features": {"msc3440_enabled": True}})
    def test_edit_thread(self) -> None:
        """Test that editing a thread works."""

        # Create a thread and edit the last event.
        channel = self._send_relation(
            RelationTypes.THREAD,
            "m.room.message",
            content={"msgtype": "m.text", "body": "A threaded reply!"},
        )
        self.assertEqual(200, channel.code, channel.json_body)
        threaded_event_id = channel.json_body["event_id"]

        new_body = {"msgtype": "m.text", "body": "I've been edited!"}
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            content={"msgtype": "m.text", "body": "foo", "m.new_content": new_body},
            parent_id=threaded_event_id,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # Fetch the thread root, to get the bundled aggregation for the thread.
        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # We expect that the edit message appears in the thread summary in the
        # unsigned relations section.
        relations_dict = channel.json_body["unsigned"].get("m.relations")
        self.assertIn(RelationTypes.THREAD, relations_dict)

        thread_summary = relations_dict[RelationTypes.THREAD]
        self.assertIn("latest_event", thread_summary)
        latest_event_in_thread = thread_summary["latest_event"]
        self.assertEqual(latest_event_in_thread["content"]["body"], "I've been edited!")

    def test_edit_edit(self) -> None:
        """Test that an edit cannot be edited."""
        new_body = {"msgtype": "m.text", "body": "Initial edit"}
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            content={
                "msgtype": "m.text",
                "body": "Wibble",
                "m.new_content": new_body,
            },
        )
        self.assertEqual(200, channel.code, channel.json_body)
        edit_event_id = channel.json_body["event_id"]

        # Edit the edit event.
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            content={
                "msgtype": "m.text",
                "body": "foo",
                "m.new_content": {"msgtype": "m.text", "body": "Ignored edit"},
            },
            parent_id=edit_event_id,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # Request the original event.
        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        # The edit to the edit should be ignored.
        self.assertEqual(channel.json_body["content"], new_body)

        # The relations information should not include the edit to the edit.
        relations_dict = channel.json_body["unsigned"].get("m.relations")
        self.assertIn(RelationTypes.REPLACE, relations_dict)

        m_replace_dict = relations_dict[RelationTypes.REPLACE]
        for key in ["event_id", "sender", "origin_server_ts"]:
            self.assertIn(key, m_replace_dict)

        self.assert_dict(
            {"event_id": edit_event_id, "sender": self.user_id}, m_replace_dict
        )

    def test_unknown_relations(self) -> None:
        """Unknown relations should be accepted."""
        channel = self._send_relation("m.relation.test", "m.room.test")
        self.assertEqual(200, channel.code, channel.json_body)
        event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/relations/{self.parent_id}?limit=1",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # We expect to get back a single pagination result, which is the full
        # relation event we sent above.
        self.assertEqual(len(channel.json_body["chunk"]), 1, channel.json_body)
        self.assert_dict(
            {"event_id": event_id, "sender": self.user_id, "type": "m.room.test"},
            channel.json_body["chunk"][0],
        )

        # We also expect to get the original event (the id of which is self.parent_id)
        self.assertEqual(
            channel.json_body["original_event"]["event_id"], self.parent_id
        )

        # When bundling the unknown relation is not included.
        channel = self.make_request(
            "GET",
            f"/rooms/{self.room}/event/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertNotIn("m.relations", channel.json_body["unsigned"])

        # But unknown relations can be directly queried.
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/aggregations/{self.parent_id}?limit=1",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertEqual(channel.json_body["chunk"], [])

    def _find_event_in_chunk(self, events: List[JsonDict]) -> JsonDict:
        """
        Find the parent event in a chunk of events and assert that it has the proper bundled aggregations.
        """
        for event in events:
            if event["event_id"] == self.parent_id:
                return event

        raise AssertionError(f"Event {self.parent_id} not found in chunk")

    def test_background_update(self) -> None:
        """Test the event_arbitrary_relations background update."""
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="👍")
        self.assertEqual(200, channel.code, channel.json_body)
        annotation_event_id_good = channel.json_body["event_id"]

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="A")
        self.assertEqual(200, channel.code, channel.json_body)
        annotation_event_id_bad = channel.json_body["event_id"]

        channel = self._send_relation(RelationTypes.THREAD, "m.room.test")
        self.assertEqual(200, channel.code, channel.json_body)
        thread_event_id = channel.json_body["event_id"]

        # Clean-up the table as if the inserts did not happen during event creation.
        self.get_success(
            self.store.db_pool.simple_delete_many(
                table="event_relations",
                column="event_id",
                iterable=(annotation_event_id_bad, thread_event_id),
                keyvalues={},
                desc="RelationsTestCase.test_background_update",
            )
        )

        # Only the "good" annotation should be found.
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/relations/{self.parent_id}?limit=10",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertEqual(
            [ev["event_id"] for ev in channel.json_body["chunk"]],
            [annotation_event_id_good],
        )

        # Insert and run the background update.
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {"update_name": "event_arbitrary_relations", "progress_json": "{}"},
            )
        )

        # Ugh, have to reset this flag
        self.store.db_pool.updates._all_done = False
        self.wait_for_background_updates()

        # The "good" annotation and the thread should be found, but not the "bad"
        # annotation.
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/relations/{self.parent_id}?limit=10",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)
        self.assertCountEqual(
            [ev["event_id"] for ev in channel.json_body["chunk"]],
            [annotation_event_id_good, thread_event_id],
        )


class RelationRedactionTestCase(BaseRelationsTestCase):
    """Test the behaviour of relations when the parent or child event is redacted."""

    def _redact(self, event_id: str) -> None:
        channel = self.make_request(
            "POST",
            f"/_matrix/client/r0/rooms/{self.room}/redact/{event_id}",
            access_token=self.user_token,
            content={},
        )
        self.assertEqual(200, channel.code, channel.json_body)

    def test_redact_relation_annotation(self) -> None:
        """Test that annotations of an event are properly handled after the
        annotation is redacted.
        """
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEqual(200, channel.code, channel.json_body)
        to_redact_event_id = channel.json_body["event_id"]

        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", "a", access_token=self.user2_token
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # Redact one of the reactions.
        self._redact(to_redact_event_id)

        # Ensure that the aggregations are correct.
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/aggregations/{self.parent_id}",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        self.assertEqual(
            channel.json_body,
            {"chunk": [{"type": "m.reaction", "key": "a", "count": 1}]},
        )

    def test_redact_relation_edit(self) -> None:
        """Test that edits of an event are redacted when the original event
        is redacted.
        """
        # Add a relation
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            parent_id=self.parent_id,
            content={
                "msgtype": "m.text",
                "body": "Wibble",
                "m.new_content": {"msgtype": "m.text", "body": "First edit"},
            },
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # Check the relation is returned
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/relations"
            f"/{self.parent_id}/m.replace/m.room.message",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        self.assertIn("chunk", channel.json_body)
        self.assertEqual(len(channel.json_body["chunk"]), 1)

        # Redact the original event
        self._redact(self.parent_id)

        # Try to check for remaining m.replace relations
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/relations"
            f"/{self.parent_id}/m.replace/m.room.message",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        # Check that no relations are returned
        self.assertIn("chunk", channel.json_body)
        self.assertEqual(channel.json_body["chunk"], [])

    def test_redact_parent(self) -> None:
        """Test that annotations of an event are redacted when the original event
        is redacted.
        """
        # Add a relation
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="👍")
        self.assertEqual(200, channel.code, channel.json_body)

        # Redact the original event.
        self._redact(self.parent_id)

        # Check that aggregations returns zero
        channel = self.make_request(
            "GET",
            f"/_matrix/client/unstable/rooms/{self.room}/aggregations/{self.parent_id}/m.annotation/m.reaction",
            access_token=self.user_token,
        )
        self.assertEqual(200, channel.code, channel.json_body)

        self.assertIn("chunk", channel.json_body)
        self.assertEqual(channel.json_body["chunk"], [])
