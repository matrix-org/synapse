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


class StatelessEventContext(object):
    """
    Attributes:
        state_group (int|None): state group id, if the state has been stored
            as a state group. This is usually only None if e.g. the event is
            an outlier.
        rejected (bool|str): A rejection reason if the event was rejected, else
            False

        push_actions (list[(str, list[object])]): list of (user_id, actions)
            tuples

        prev_group (int): Previously persisted state group. ``None`` for an
            outlier.

        prev_state_events (?): XXX: is this ever set to anything other than
            the empty list?
    """

    __slots__ = [
        "state_group",
        "rejected",
        "prev_group",
        "prev_state_events",
        "app_service",
    ]

    def __init__(self):
        self.state_group = None

        self.rejected = False

        # A previously persisted state group and a delta between that
        # and this state.
        self.prev_group = None

        self.prev_state_events = None

        self.app_service = None

    def serialize(self):
        """Converts self to a type that can be serialized as JSON, and then
        deserialized by `deserialize`

        Returns:
            dict
        """
        return {
            "state_group": self.state_group,
            "rejected": self.rejected,
            "prev_group": self.prev_group,
            "prev_state_events": self.prev_state_events,
            "app_service_id": self.app_service.id if self.app_service else None
        }

    @staticmethod
    def deserialize(store, input):
        """Converts a dict that was produced by `serialize` back into a
        EventContext.

        Args:
            store (DataStore): Used to convert AS ID to AS object
            input (dict): A dict produced by `serialize`

        Returns:
            EventContext
        """
        context = StatelessEventContext()
        context.state_group = input["state_group"]
        context.rejected = input["rejected"]
        context.prev_group = input["prev_group"]
        context.prev_state_events = input["prev_state_events"]

        app_service_id = input["app_service_id"]
        if app_service_id:
            context.app_service = store.get_app_service_by_id(app_service_id)

        return context


class EventContext(StatelessEventContext):
    """
    Attributes:
        current_state_ids (dict[(str, str), str]):
            The current state map including the current event.
            (type, state_key) -> event_id

        prev_state_ids (dict[(str, str), str]):
            The current state map excluding the current event.
            (type, state_key) -> event_id

        delta_ids (dict[(str, str), str]): Delta from ``prev_group``.
            (type, state_key) -> event_id. ``None`` for an outlier.

    """

    __slots__ = [
        "current_state_ids",
        "prev_state_ids",
        "delta_ids",
    ]

    def __init__(self):
        # The current state including the current event
        self.current_state_ids = None
        # The current state excluding the current event
        self.prev_state_ids = None

        self.delta_ids = None

        super(EventContext, self).__init__()
