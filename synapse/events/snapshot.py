# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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


class EventContext(object):
    """
    Attributes:
        current_state_ids (dict[(str, str), str]):
            The current state map including the current event.
            (type, state_key) -> event_id

        prev_state_ids (dict[(str, str), str]):
            The current state map excluding the current event.
            (type, state_key) -> event_id

        state_group (int): state group id
        rejected (bool|str): A rejection reason if the event was rejected, else
            False

        push_actions (list[(str, list[object])]): list of (user_id, actions)
            tuples

        prev_group (int): Previously persisted state group. ``None`` for an
            outlier.
        delta_ids (dict[(str, str), str]): Delta from ``prev_group``.
            (type, state_key) -> event_id. ``None`` for an outlier.

        prev_state_events (?): XXX: is this ever set to anything other than
            the empty list?
    """

    __slots__ = [
        "current_state_ids",
        "prev_state_ids",
        "state_group",
        "rejected",
        "push_actions",
        "prev_group",
        "delta_ids",
        "prev_state_events",
        "app_service",
    ]

    def __init__(self):
        # The current state including the current event
        self.current_state_ids = None
        # The current state excluding the current event
        self.prev_state_ids = None
        self.state_group = None

        self.rejected = False
        self.push_actions = []

        # A previously persisted state group and a delta between that
        # and this state.
        self.prev_group = None
        self.delta_ids = None

        self.prev_state_events = None

        self.app_service = None
