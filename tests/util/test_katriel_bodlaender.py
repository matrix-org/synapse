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

from synapse.util.katriel_bodlaender import InMemoryOrderedListStore

from tests import unittest


class KatrielBodlaenderTests(unittest.TestCase):
    def test_simple_graph(self):
        store = InMemoryOrderedListStore()

        nodes = [
            "node_1",
            "node_2",
            "node_3",
            "node_4",
        ]

        for node in nodes:
            store.add_node(node)

        store.add_edge("node_2", "node_3")
        store.add_edge("node_1", "node_2")
        store.add_edge("node_3", "node_4")

        self.assertEqual(nodes, store.list)

    def test_reverse_graph(self):
        store = InMemoryOrderedListStore()

        nodes = [
            "node_1",
            "node_2",
            "node_3",
            "node_4",
        ]

        for node in nodes:
            store.add_node(node)

        store.add_edge("node_3", "node_2")
        store.add_edge("node_2", "node_1")
        store.add_edge("node_4", "node_3")

        self.assertEqual(list(reversed(nodes)), store.list)
