# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
import json
import urllib

from synapse.api.constants import EventTypes, RelationTypes
from synapse.rest import admin
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import register, relations

from tests import unittest


class RelationsTestCase(unittest.HomeserverTestCase):
    servlets = [
        relations.register_servlets,
        room.register_servlets,
        login.register_servlets,
        register.register_servlets,
        admin.register_servlets_for_client_rest_resource,
    ]
    hijack_auth = False

    def make_homeserver(self, reactor, clock):
        # We need to enable msc1849 support for aggregations
        config = self.default_config()
        config["experimental_msc1849_support_enabled"] = True
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor, clock, hs):
        self.user_id, self.user_token = self._create_user("alice")
        self.user2_id, self.user2_token = self._create_user("bob")

        self.room = self.helper.create_room_as(self.user_id, tok=self.user_token)
        self.helper.join(self.room, user=self.user2_id, tok=self.user2_token)
        res = self.helper.send(self.room, body="Hi!", tok=self.user_token)
        self.parent_id = res["event_id"]

    def test_send_relation(self):
        """Tests that sending a relation using the new /send_relation works
        creates the right shape of event.
        """

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="👍")
        self.assertEquals(200, channel.code, channel.json_body)

        event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            "/rooms/%s/event/%s" % (self.room, event_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

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

    def test_deny_membership(self):
        """Test that we deny relations on membership events"""
        channel = self._send_relation(RelationTypes.ANNOTATION, EventTypes.Member)
        self.assertEquals(400, channel.code, channel.json_body)

    def test_deny_double_react(self):
        """Test that we deny relations on membership events"""
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="a")
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEquals(400, channel.code, channel.json_body)

    def test_basic_paginate_relations(self):
        """Tests that calling pagination API correctly the latest relations."""
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction")
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction")
        self.assertEquals(200, channel.code, channel.json_body)
        annotation_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/rooms/%s/relations/%s?limit=1"
            % (self.room, self.parent_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

        # We expect to get back a single pagination result, which is the full
        # relation event we sent above.
        self.assertEquals(len(channel.json_body["chunk"]), 1, channel.json_body)
        self.assert_dict(
            {"event_id": annotation_id, "sender": self.user_id, "type": "m.reaction"},
            channel.json_body["chunk"][0],
        )

        # We also expect to get the original event (the id of which is self.parent_id)
        self.assertEquals(
            channel.json_body["original_event"]["event_id"], self.parent_id
        )

        # Make sure next_batch has something in it that looks like it could be a
        # valid token.
        self.assertIsInstance(
            channel.json_body.get("next_batch"), str, channel.json_body
        )

    def test_repeated_paginate_relations(self):
        """Test that if we paginate using a limit and tokens then we get the
        expected events.
        """

        expected_event_ids = []
        for _ in range(10):
            channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction")
            self.assertEquals(200, channel.code, channel.json_body)
            expected_event_ids.append(channel.json_body["event_id"])

        prev_token = None
        found_event_ids = []
        for _ in range(20):
            from_token = ""
            if prev_token:
                from_token = "&from=" + prev_token

            channel = self.make_request(
                "GET",
                "/_matrix/client/unstable/rooms/%s/relations/%s?limit=1%s"
                % (self.room, self.parent_id, from_token),
                access_token=self.user_token,
            )
            self.assertEquals(200, channel.code, channel.json_body)

            found_event_ids.extend(e["event_id"] for e in channel.json_body["chunk"])
            next_batch = channel.json_body.get("next_batch")

            self.assertNotEquals(prev_token, next_batch)
            prev_token = next_batch

            if not prev_token:
                break

        # We paginated backwards, so reverse
        found_event_ids.reverse()
        self.assertEquals(found_event_ids, expected_event_ids)

    def test_aggregation_pagination_groups(self):
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
            self.assertEquals(200, channel.code, channel.json_body)

            idx += 1
            idx %= len(access_tokens)

        prev_token = None
        found_groups = {}
        for _ in range(20):
            from_token = ""
            if prev_token:
                from_token = "&from=" + prev_token

            channel = self.make_request(
                "GET",
                "/_matrix/client/unstable/rooms/%s/aggregations/%s?limit=1%s"
                % (self.room, self.parent_id, from_token),
                access_token=self.user_token,
            )
            self.assertEquals(200, channel.code, channel.json_body)

            self.assertEqual(len(channel.json_body["chunk"]), 1, channel.json_body)

            for groups in channel.json_body["chunk"]:
                # We only expect reactions
                self.assertEqual(groups["type"], "m.reaction", channel.json_body)

                # We should only see each key once
                self.assertNotIn(groups["key"], found_groups, channel.json_body)

                found_groups[groups["key"]] = groups["count"]

            next_batch = channel.json_body.get("next_batch")

            self.assertNotEquals(prev_token, next_batch)
            prev_token = next_batch

            if not prev_token:
                break

        self.assertEquals(sent_groups, found_groups)

    def test_aggregation_pagination_within_group(self):
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
            self.assertEquals(200, channel.code, channel.json_body)
            expected_event_ids.append(channel.json_body["event_id"])

            idx += 1

        # Also send a different type of reaction so that we test we don't see it
        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", key="a")
        self.assertEquals(200, channel.code, channel.json_body)

        prev_token = None
        found_event_ids = []
        encoded_key = urllib.parse.quote_plus("👍".encode("utf-8"))
        for _ in range(20):
            from_token = ""
            if prev_token:
                from_token = "&from=" + prev_token

            channel = self.make_request(
                "GET",
                "/_matrix/client/unstable/rooms/%s"
                "/aggregations/%s/%s/m.reaction/%s?limit=1%s"
                % (
                    self.room,
                    self.parent_id,
                    RelationTypes.ANNOTATION,
                    encoded_key,
                    from_token,
                ),
                access_token=self.user_token,
            )
            self.assertEquals(200, channel.code, channel.json_body)

            self.assertEqual(len(channel.json_body["chunk"]), 1, channel.json_body)

            found_event_ids.extend(e["event_id"] for e in channel.json_body["chunk"])

            next_batch = channel.json_body.get("next_batch")

            self.assertNotEquals(prev_token, next_batch)
            prev_token = next_batch

            if not prev_token:
                break

        # We paginated backwards, so reverse
        found_event_ids.reverse()
        self.assertEquals(found_event_ids, expected_event_ids)

    def test_aggregation(self):
        """Test that annotations get correctly aggregated."""

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", "a", access_token=self.user2_token
        )
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "b")
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/rooms/%s/aggregations/%s"
            % (self.room, self.parent_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

        self.assertEquals(
            channel.json_body,
            {
                "chunk": [
                    {"type": "m.reaction", "key": "a", "count": 2},
                    {"type": "m.reaction", "key": "b", "count": 1},
                ]
            },
        )

    def test_aggregation_redactions(self):
        """Test that annotations get correctly aggregated after a redaction."""

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEquals(200, channel.code, channel.json_body)
        to_redact_event_id = channel.json_body["event_id"]

        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", "a", access_token=self.user2_token
        )
        self.assertEquals(200, channel.code, channel.json_body)

        # Now lets redact one of the 'a' reactions
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/%s/redact/%s" % (self.room, to_redact_event_id),
            access_token=self.user_token,
            content={},
        )
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/rooms/%s/aggregations/%s"
            % (self.room, self.parent_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

        self.assertEquals(
            channel.json_body,
            {"chunk": [{"type": "m.reaction", "key": "a", "count": 1}]},
        )

    def test_aggregation_must_be_annotation(self):
        """Test that aggregations must be annotations."""

        channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/rooms/%s/aggregations/%s/%s?limit=1"
            % (self.room, self.parent_id, RelationTypes.REPLACE),
            access_token=self.user_token,
        )
        self.assertEquals(400, channel.code, channel.json_body)

    def test_aggregation_get_event(self):
        """Test that annotations and references get correctly bundled when
        getting the parent event.
        """

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "a")
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", "a", access_token=self.user2_token
        )
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.ANNOTATION, "m.reaction", "b")
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self._send_relation(RelationTypes.REFERENCE, "m.room.test")
        self.assertEquals(200, channel.code, channel.json_body)
        reply_1 = channel.json_body["event_id"]

        channel = self._send_relation(RelationTypes.REFERENCE, "m.room.test")
        self.assertEquals(200, channel.code, channel.json_body)
        reply_2 = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            "/rooms/%s/event/%s" % (self.room, self.parent_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

        self.assertEquals(
            channel.json_body["unsigned"].get("m.relations"),
            {
                RelationTypes.ANNOTATION: {
                    "chunk": [
                        {"type": "m.reaction", "key": "a", "count": 2},
                        {"type": "m.reaction", "key": "b", "count": 1},
                    ]
                },
                RelationTypes.REFERENCE: {
                    "chunk": [{"event_id": reply_1}, {"event_id": reply_2}]
                },
            },
        )

    def test_edit(self):
        """Test that a simple edit works."""

        new_body = {"msgtype": "m.text", "body": "I've been edited!"}
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            content={"msgtype": "m.text", "body": "foo", "m.new_content": new_body},
        )
        self.assertEquals(200, channel.code, channel.json_body)

        edit_event_id = channel.json_body["event_id"]

        channel = self.make_request(
            "GET",
            "/rooms/%s/event/%s" % (self.room, self.parent_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

        self.assertEquals(channel.json_body["content"], new_body)

        relations_dict = channel.json_body["unsigned"].get("m.relations")
        self.assertIn(RelationTypes.REPLACE, relations_dict)

        m_replace_dict = relations_dict[RelationTypes.REPLACE]
        for key in ["event_id", "sender", "origin_server_ts"]:
            self.assertIn(key, m_replace_dict)

        self.assert_dict(
            {"event_id": edit_event_id, "sender": self.user_id}, m_replace_dict
        )

    def test_multi_edit(self):
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
        self.assertEquals(200, channel.code, channel.json_body)

        new_body = {"msgtype": "m.text", "body": "I've been edited!"}
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            content={"msgtype": "m.text", "body": "foo", "m.new_content": new_body},
        )
        self.assertEquals(200, channel.code, channel.json_body)

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
        self.assertEquals(200, channel.code, channel.json_body)

        channel = self.make_request(
            "GET",
            "/rooms/%s/event/%s" % (self.room, self.parent_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

        self.assertEquals(channel.json_body["content"], new_body)

        relations_dict = channel.json_body["unsigned"].get("m.relations")
        self.assertIn(RelationTypes.REPLACE, relations_dict)

        m_replace_dict = relations_dict[RelationTypes.REPLACE]
        for key in ["event_id", "sender", "origin_server_ts"]:
            self.assertIn(key, m_replace_dict)

        self.assert_dict(
            {"event_id": edit_event_id, "sender": self.user_id}, m_replace_dict
        )

    def test_relations_redaction_redacts_edits(self):
        """Test that edits of an event are redacted when the original event
        is redacted.
        """
        # Send a new event
        res = self.helper.send(self.room, body="Heyo!", tok=self.user_token)
        original_event_id = res["event_id"]

        # Add a relation
        channel = self._send_relation(
            RelationTypes.REPLACE,
            "m.room.message",
            parent_id=original_event_id,
            content={
                "msgtype": "m.text",
                "body": "Wibble",
                "m.new_content": {"msgtype": "m.text", "body": "First edit"},
            },
        )
        self.assertEquals(200, channel.code, channel.json_body)

        # Check the relation is returned
        channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/rooms/%s/relations/%s/m.replace/m.room.message"
            % (self.room, original_event_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

        self.assertIn("chunk", channel.json_body)
        self.assertEquals(len(channel.json_body["chunk"]), 1)

        # Redact the original event
        channel = self.make_request(
            "PUT",
            "/rooms/%s/redact/%s/%s"
            % (self.room, original_event_id, "test_relations_redaction_redacts_edits"),
            access_token=self.user_token,
            content="{}",
        )
        self.assertEquals(200, channel.code, channel.json_body)

        # Try to check for remaining m.replace relations
        channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/rooms/%s/relations/%s/m.replace/m.room.message"
            % (self.room, original_event_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

        # Check that no relations are returned
        self.assertIn("chunk", channel.json_body)
        self.assertEquals(channel.json_body["chunk"], [])

    def test_aggregations_redaction_prevents_access_to_aggregations(self):
        """Test that annotations of an event are redacted when the original event
        is redacted.
        """
        # Send a new event
        res = self.helper.send(self.room, body="Hello!", tok=self.user_token)
        original_event_id = res["event_id"]

        # Add a relation
        channel = self._send_relation(
            RelationTypes.ANNOTATION, "m.reaction", key="👍", parent_id=original_event_id
        )
        self.assertEquals(200, channel.code, channel.json_body)

        # Redact the original
        channel = self.make_request(
            "PUT",
            "/rooms/%s/redact/%s/%s"
            % (
                self.room,
                original_event_id,
                "test_aggregations_redaction_prevents_access_to_aggregations",
            ),
            access_token=self.user_token,
            content="{}",
        )
        self.assertEquals(200, channel.code, channel.json_body)

        # Check that aggregations returns zero
        channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/rooms/%s/aggregations/%s/m.annotation/m.reaction"
            % (self.room, original_event_id),
            access_token=self.user_token,
        )
        self.assertEquals(200, channel.code, channel.json_body)

        self.assertIn("chunk", channel.json_body)
        self.assertEquals(channel.json_body["chunk"], [])

    def _send_relation(
        self,
        relation_type,
        event_type,
        key=None,
        content={},
        access_token=None,
        parent_id=None,
    ):
        """Helper function to send a relation pointing at `self.parent_id`

        Args:
            relation_type (str): One of `RelationTypes`
            event_type (str): The type of the event to create
            parent_id (str): The event_id this relation relates to. If None, then self.parent_id
            key (str|None): The aggregation key used for m.annotation relation
                type.
            content(dict|None): The content of the created event.
            access_token (str|None): The access token used to send the relation,
                defaults to `self.user_token`

        Returns:
            FakeChannel
        """
        if not access_token:
            access_token = self.user_token

        query = ""
        if key:
            query = "?key=" + urllib.parse.quote_plus(key.encode("utf-8"))

        original_id = parent_id if parent_id else self.parent_id

        channel = self.make_request(
            "POST",
            "/_matrix/client/unstable/rooms/%s/send_relation/%s/%s/%s%s"
            % (self.room, original_id, relation_type, event_type, query),
            json.dumps(content).encode("utf-8"),
            access_token=access_token,
        )
        return channel

    def _create_user(self, localpart):
        user_id = self.register_user(localpart, "abc123")
        access_token = self.login(localpart, "abc123")

        return user_id, access_token
