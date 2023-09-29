# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import MAIN_TIMELINE
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest


class RelationsStoreTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        """
        Creates a DAG:

            A <---[m.thread]-- B <--[m.annotation]-- C
            ^
            |--[m.reference]-- D <--[m.annotation]-- E

            F <--[m.annotation]-- G

        """
        self._main_store = self.hs.get_datastores().main

        self._create_relation("A", "B", "m.thread")
        self._create_relation("B", "C", "m.annotation")
        self._create_relation("A", "D", "m.reference")
        self._create_relation("D", "E", "m.annotation")
        self._create_relation("F", "G", "m.annotation")

    def _create_relation(self, parent_id: str, event_id: str, rel_type: str) -> None:
        self.get_success(
            self._main_store.db_pool.simple_insert(
                table="event_relations",
                values={
                    "event_id": event_id,
                    "relates_to_id": parent_id,
                    "relation_type": rel_type,
                },
            )
        )

    def test_get_thread_id(self) -> None:
        """
        Ensure that get_thread_id only searches up the tree for threads.
        """
        # The thread itself and children of it return the thread.
        thread_id = self.get_success(self._main_store.get_thread_id("B"))
        self.assertEqual("A", thread_id)

        thread_id = self.get_success(self._main_store.get_thread_id("C"))
        self.assertEqual("A", thread_id)

        # But the root and events related to the root do not.
        thread_id = self.get_success(self._main_store.get_thread_id("A"))
        self.assertEqual(MAIN_TIMELINE, thread_id)

        thread_id = self.get_success(self._main_store.get_thread_id("D"))
        self.assertEqual(MAIN_TIMELINE, thread_id)

        thread_id = self.get_success(self._main_store.get_thread_id("E"))
        self.assertEqual(MAIN_TIMELINE, thread_id)

        # Events which are not related to a thread at all should return the
        # main timeline.
        thread_id = self.get_success(self._main_store.get_thread_id("F"))
        self.assertEqual(MAIN_TIMELINE, thread_id)

        thread_id = self.get_success(self._main_store.get_thread_id("G"))
        self.assertEqual(MAIN_TIMELINE, thread_id)

    def test_get_thread_id_for_receipts(self) -> None:
        """
        Ensure that get_thread_id_for_receipts searches up and down the tree for a thread.
        """
        # All of the events are considered related to this thread.
        thread_id = self.get_success(self._main_store.get_thread_id_for_receipts("A"))
        self.assertEqual("A", thread_id)

        thread_id = self.get_success(self._main_store.get_thread_id_for_receipts("B"))
        self.assertEqual("A", thread_id)

        thread_id = self.get_success(self._main_store.get_thread_id_for_receipts("C"))
        self.assertEqual("A", thread_id)

        thread_id = self.get_success(self._main_store.get_thread_id_for_receipts("D"))
        self.assertEqual("A", thread_id)

        thread_id = self.get_success(self._main_store.get_thread_id_for_receipts("E"))
        self.assertEqual("A", thread_id)

        # Events which are not related to a thread at all should return the
        # main timeline.
        thread_id = self.get_success(self._main_store.get_thread_id("F"))
        self.assertEqual(MAIN_TIMELINE, thread_id)

        thread_id = self.get_success(self._main_store.get_thread_id("G"))
        self.assertEqual(MAIN_TIMELINE, thread_id)
