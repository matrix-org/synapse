# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from twisted.internet import defer
from twisted.trial import unittest

from synapse.state import StateHandler
from synapse.storage.pdu import PduEntry
from synapse.federation.pdu_codec import encode_event_id

from collections import namedtuple

from mock import Mock


ReturnType = namedtuple(
    "StateReturnType", ["new_branch", "current_branch"]
)


class StateTestCase(unittest.TestCase):
    def setUp(self):
        self.persistence = Mock(spec=[
            "get_unresolved_state_tree",
            "update_current_state",
            "get_latest_pdus_in_context",
            "get_current_state_pdu",
            "get_pdu",
        ])
        self.replication = Mock(spec=["get_pdu"])

        hs = Mock(spec=["get_datastore", "get_replication_layer"])
        hs.get_datastore.return_value = self.persistence
        hs.get_replication_layer.return_value = self.replication
        hs.hostname = "bob.com"

        self.state = StateHandler(hs)

    @defer.inlineCallbacks
    def test_new_state_key(self):
        # We've never seen anything for this state before
        new_pdu = new_fake_pdu_entry("A", "test", "mem", "x", None, 10)

        self.persistence.get_unresolved_state_tree.return_value = (
            ReturnType([new_pdu], [])
        )

        is_new = yield self.state.handle_new_state(new_pdu)

        self.assertTrue(is_new)

        self.persistence.get_unresolved_state_tree.assert_called_once_with(
            new_pdu
        )

        self.assertEqual(1, self.persistence.update_current_state.call_count)

        self.assertFalse(self.replication.get_pdu.called)

    @defer.inlineCallbacks
    def test_direct_overwrite(self):
        # We do a direct overwriting of the old state, i.e., the new state
        # points to the old state.

        old_pdu = new_fake_pdu_entry("A", "test", "mem", "x", None, 10)
        new_pdu = new_fake_pdu_entry("B", "test", "mem", "x", "A", 5)

        self.persistence.get_unresolved_state_tree.return_value = (
            ReturnType([new_pdu, old_pdu], [old_pdu])
        )

        is_new = yield self.state.handle_new_state(new_pdu)

        self.assertTrue(is_new)

        self.persistence.get_unresolved_state_tree.assert_called_once_with(
            new_pdu
        )

        self.assertEqual(1, self.persistence.update_current_state.call_count)

        self.assertFalse(self.replication.get_pdu.called)

    @defer.inlineCallbacks
    def test_power_level_fail(self):
        # We try to update the state based on an outdated state, and have a
        # too low power level.

        old_pdu_1 = new_fake_pdu_entry("A", "test", "mem", "x", None, 10)
        old_pdu_2 = new_fake_pdu_entry("B", "test", "mem", "x", None, 10)
        new_pdu = new_fake_pdu_entry("C", "test", "mem", "x", "A", 5)

        self.persistence.get_unresolved_state_tree.return_value = (
            ReturnType([new_pdu, old_pdu_1], [old_pdu_2, old_pdu_1])
        )

        is_new = yield self.state.handle_new_state(new_pdu)

        self.assertFalse(is_new)

        self.persistence.get_unresolved_state_tree.assert_called_once_with(
            new_pdu
        )

        self.assertEqual(0, self.persistence.update_current_state.call_count)

        self.assertFalse(self.replication.get_pdu.called)

    @defer.inlineCallbacks
    def test_power_level_succeed(self):
        # We try to update the state based on an outdated state, but have
        # sufficient power level to force the update.

        old_pdu_1 = new_fake_pdu_entry("A", "test", "mem", "x", None, 10)
        old_pdu_2 = new_fake_pdu_entry("B", "test", "mem", "x", None, 10)
        new_pdu = new_fake_pdu_entry("C", "test", "mem", "x", "A", 15)

        self.persistence.get_unresolved_state_tree.return_value = (
            ReturnType([new_pdu, old_pdu_1], [old_pdu_2, old_pdu_1])
        )

        is_new = yield self.state.handle_new_state(new_pdu)

        self.assertTrue(is_new)

        self.persistence.get_unresolved_state_tree.assert_called_once_with(
            new_pdu
        )

        self.assertEqual(1, self.persistence.update_current_state.call_count)

        self.assertFalse(self.replication.get_pdu.called)

    @defer.inlineCallbacks
    def test_power_level_equal_same_len(self):
        # We try to update the state based on an outdated state, the power
        # levels are the same and so are the branch lengths

        old_pdu_1 = new_fake_pdu_entry("A", "test", "mem", "x", None, 10)
        old_pdu_2 = new_fake_pdu_entry("B", "test", "mem", "x", None, 10)
        new_pdu = new_fake_pdu_entry("C", "test", "mem", "x", "A", 10)

        self.persistence.get_unresolved_state_tree.return_value = (
            ReturnType([new_pdu, old_pdu_1], [old_pdu_2, old_pdu_1])
        )

        is_new = yield self.state.handle_new_state(new_pdu)

        self.assertTrue(is_new)

        self.persistence.get_unresolved_state_tree.assert_called_once_with(
            new_pdu
        )

        self.assertEqual(1, self.persistence.update_current_state.call_count)

        self.assertFalse(self.replication.get_pdu.called)

    @defer.inlineCallbacks
    def test_power_level_equal_diff_len(self):
        # We try to update the state based on an outdated state, the power
        # levels are the same but the branch length of the new one is longer.

        old_pdu_1 = new_fake_pdu_entry("A", "test", "mem", "x", None, 10)
        old_pdu_2 = new_fake_pdu_entry("B", "test", "mem", "x", None, 10)
        old_pdu_3 = new_fake_pdu_entry("C", "test", "mem", "x", "A", 10)
        new_pdu = new_fake_pdu_entry("D", "test", "mem", "x", "C", 10)

        self.persistence.get_unresolved_state_tree.return_value = (
            ReturnType([new_pdu, old_pdu_3, old_pdu_1], [old_pdu_2, old_pdu_1])
        )

        is_new = yield self.state.handle_new_state(new_pdu)

        self.assertTrue(is_new)

        self.persistence.get_unresolved_state_tree.assert_called_once_with(
            new_pdu
        )

        self.assertEqual(1, self.persistence.update_current_state.call_count)

        self.assertFalse(self.replication.get_pdu.called)

    @defer.inlineCallbacks
    def test_missing_pdu(self):
        # We try to update state against a PDU we haven't yet seen,
        # triggering a get_pdu request

        # The pdu we haven't seen
        old_pdu_1 = new_fake_pdu_entry("A", "test", "mem", "x", None, 10)

        old_pdu_2 = new_fake_pdu_entry("B", "test", "mem", "x", None, 10)
        new_pdu = new_fake_pdu_entry("C", "test", "mem", "x", "A", 20)

        # The return_value of `get_unresolved_state_tree`, which changes after
        # the call to get_pdu
        tree_to_return = [ReturnType([new_pdu], [old_pdu_2])]

        def return_tree(p):
            return tree_to_return[0]

        def set_return_tree(*args, **kwargs):
            tree_to_return[0] = ReturnType(
                [new_pdu, old_pdu_1], [old_pdu_2, old_pdu_1]
            )

        self.persistence.get_unresolved_state_tree.side_effect = return_tree

        self.replication.get_pdu.side_effect = set_return_tree

        self.persistence.get_pdu.return_value = None

        is_new = yield self.state.handle_new_state(new_pdu)

        self.assertTrue(is_new)

        self.persistence.get_unresolved_state_tree.assert_called_with(
            new_pdu
        )

        self.assertEquals(
            2, self.persistence.get_unresolved_state_tree.call_count
        )

        self.assertEqual(1, self.persistence.update_current_state.call_count)

    @defer.inlineCallbacks
    def test_new_event(self):
        event = Mock()
        event.event_id = "12123123@test"

        state_pdu = new_fake_pdu_entry("C", "test", "mem", "x", "A", 20)

        snapshot = Mock()
        snapshot.prev_state_pdu = state_pdu
        event_id = "pdu_id@origin.com"

        def fill_out_prev_events(event):
            event.prev_events = [event_id]
            event.depth = 6
        snapshot.fill_out_prev_events = fill_out_prev_events

        yield self.state.handle_new_event(event, snapshot)

        self.assertLess(5, event.depth)

        self.assertEquals(1, len(event.prev_events))

        prev_id = event.prev_events[0]

        self.assertEqual(event_id, prev_id)

        self.assertEqual(
            encode_event_id(state_pdu.pdu_id, state_pdu.origin),
            event.prev_state
        )


def new_fake_pdu_entry(pdu_id, context, pdu_type, state_key, prev_state_id,
                 power_level):
    new_pdu = PduEntry(
        pdu_id=pdu_id,
        pdu_type=pdu_type,
        state_key=state_key,
        power_level=power_level,
        prev_state_id=prev_state_id,
        origin="example.com",
        context="context",
        ts=1405353060021,
        depth=0,
        content_json="{}",
        unrecognized_keys="{}",
        outlier=True,
        is_state=True,
        prev_state_origin="example.com",
        have_processed=True,
    )

    return new_pdu
