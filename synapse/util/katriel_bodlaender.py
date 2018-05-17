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

"""This module contains an implementation of the Katriel-Bodlaender algorithm,
which is used to do online topological ordering of graphs.

Note that the ordering derived from the graph has the first node one with no
incoming edges at the start, and the last node one with no outgoing edges.

This ordering is therefore opposite to what one might expect when considering
the room DAG, as newer messages would be added to the start rather than the
end.

***We therefore invert the direction of edges when using the algorithm***

See https://www.sciencedirect.com/science/article/pii/S0304397507006573
"""

from abc import ABCMeta, abstractmethod


class OrderedListStore(object):
    """An abstract base class that is used to store a topological ordering of
    a graph. Suitable for use with the Katriel-Bodlaender algorithm.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def is_before(self, first_node, second_node):
        """Returns whether the first node is before the second node.

        Args:
            first_node (str)
            second_node (str)

        Returns:
            bool: True if first_node is before second_node
        """
        pass

    @abstractmethod
    def get_prev(self, node_id):
        """Gets the node immediately before the given node

        Args:
            node_id (str)

        Returns:
            str|None: A node ID or None if no preceding node exists
        """
        pass

    @abstractmethod
    def get_next(self, node_id):
        """Gets the node immediately after the given node

        Args:
            node_id (str)

        Returns:
            str|None: A node ID or None if no proceding node exists
        """
        pass

    @abstractmethod
    def insert_before(self, node_id, target_id):
        """Inserts node immediately before target node.

        If target_id is None then the node is inserted at the end of the list

        Args:
            node_id (str)
            target_id (str|None)
        """
        pass

    @abstractmethod
    def insert_after(self, node_id, target_id):
        """Inserts node immediately after target node.

        If target_id is None then the node is inserted at the start of the list

        Args:
            node_id (str)
            target_id (str|None)
        """
        pass

    @abstractmethod
    def get_nodes_with_edges_to(self, node_id):
        """Get all nodes with edges to the given node

        Args:
            node_id (str)

        Returns:
            list[tuple[float, str]]: Returns a list of tuple of an ordering
            term and the node ID. The ordering term can be used to sort the
            returned list.
            The ordering is valid until subsequent calls to insert_* functions
        """
        pass

    @abstractmethod
    def get_nodes_with_edges_from(self, node_id):
        """Get all nodes with edges from the given node

        Args:
            node_id (str)

        Returns:
            list[tuple[float, str]]: Returns a list of tuple of an ordering
            term and the node ID. The ordering term can be used to sort the
            returned list.
            The ordering is valid until subsequent calls to insert_* functions
        """
        pass

    @abstractmethod
    def _delete_ordering(self, node_id):
        """Deletes the given node from the ordered list (but not the graph).

        Used when we want to reinsert it into a different position

        Args:
            node_id (str)
        """
        pass

    @abstractmethod
    def _add_edge_to_graph(self, source_id, target_id):
        """Adds an edge to the graph from source to target.

        Does not update ordering.

        Args:
            source_id (str)
            target_id (str)
        """
        pass

    def add_node(self, node_id):
        """Adds a node to the graph.

        Args:
            node_id (str)
        """
        self.insert_before(node_id, None)

    def add_edge(self, source, target):
        """Adds a new edge is added to the graph and updates the ordering.

        See module level docs.

        Note that both the source and target nodes must have been inserted into
        the store (at an arbitrary position) already.

        Args:
            source (str): The source node of the new edge
            target (str): The target node of the new edge
        """

        # The following is the Katriel-Bodlaender algorithm.

        to_s = []
        from_t = []
        to_s_neighbours = []
        from_t_neighbours = []
        to_s_indegree = 0
        from_t_outdegree = 0
        s = source
        t = target

        while s and t and not self.is_before(s, t):
            m_s = to_s_indegree
            m_t = from_t_outdegree

            pe_s = self.get_nodes_with_edges_to(s)
            fe_t = self.get_nodes_with_edges_from(t)

            l_s = len(pe_s)
            l_t = len(fe_t)

            if m_s + l_s <= m_t + l_t:
                to_s.append(s)
                to_s_neighbours.extend(pe_s)
                to_s_indegree += l_s

                if to_s_neighbours:
                    to_s_neighbours.sort()
                    _, s = to_s_neighbours.pop()
                else:
                    s = None

            if m_s + l_s >= m_t + l_t:
                from_t.append(t)
                from_t_neighbours.extend(fe_t)
                from_t_outdegree += l_t

                if from_t_neighbours:
                    from_t_neighbours.sort(reverse=True)
                    _, t = from_t_neighbours.pop()
                else:
                    t = None

        if s is None:
            s = self.get_prev(target)

        if t is None:
            t = self.get_next(source)

        while to_s:
            s1 = to_s.pop()
            self._delete_ordering(s1)
            self.insert_after(s1, s)
            s = s1

        while from_t:
            t1 = from_t.pop()
            self._delete_ordering(t1)
            self.insert_before(t1, t)
            t = t1

        self._add_edge_to_graph(source, target)


class InMemoryOrderedListStore(OrderedListStore):
    """An in memory OrderedListStore
    """

    def __init__(self):
        # The ordered list of nodes
        self.list = []

        # Map from node to set of nodes that it references
        self.edges_from = {}

        # Map from node to set of nodes that it is referenced by
        self.edges_to = {}

    def is_before(self, first_node, second_node):
        return self.list.index(first_node) < self.list.index(second_node)

    def get_prev(self, node_id):
        idx = self.list.index(node_id) - 1
        if idx >= 0:
            return self.list[idx]
        else:
            return None

    def get_next(self, node_id):
        idx = self.list.index(node_id) + 1
        if idx < len(self.list):
            return self.list[idx]
        else:
            return None

    def insert_before(self, node_id, target_id):
        if target_id is not None:
            idx = self.list.index(target_id)
            self.list.insert(idx, node_id)
        else:
            self.list.append(node_id)

    def insert_after(self, node_id, target_id):
        if target_id is not None:
            idx = self.list.index(target_id) + 1
            self.list.insert(idx, node_id)
        else:
            self.list.insert(0, node_id)

    def _delete_ordering(self, node_id):
        self.list.remove(node_id)

    def get_nodes_with_edges_to(self, node_id):
        to_nodes = self.edges_to.get(node_id, [])
        return [(self.list.index(nid), nid) for nid in to_nodes]

    def get_nodes_with_edges_from(self, node_id):
        from_nodes = self.edges_from.get(node_id, [])
        return [(self.list.index(nid), nid) for nid in from_nodes]

    def _add_edge_to_graph(self, source_id, target_id):
        self.edges_from.setdefault(source_id, set()).add(target_id)
        self.edges_to.setdefault(target_id, set()).add(source_id)
