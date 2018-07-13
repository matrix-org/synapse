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

from frozendict import frozendict

from twisted.internet import defer


class EventContext(object):
    """
    Attributes:
        current_state_ids (dict[(str, str), str]):
            The current state map including the current event.
            (type, state_key) -> event_id

        prev_state_ids (dict[(str, str), str]):
            The current state map excluding the current event.
            (type, state_key) -> event_id

        state_group (int|None): state group id, if the state has been stored
            as a state group. This is usually only None if e.g. the event is
            an outlier.
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

        # A previously persisted state group and a delta between that
        # and this state.
        self.prev_group = None
        self.delta_ids = None

        self.prev_state_events = None

        self.app_service = None

    def serialize(self, event):
        """Converts self to a type that can be serialized as JSON, and then
        deserialized by `deserialize`

        Args:
            event (FrozenEvent): The event that this context relates to

        Returns:
            dict
        """

        # We don't serialize the full state dicts, instead they get pulled out
        # of the DB on the other side. However, the other side can't figure out
        # the prev_state_ids, so if we're a state event we include the event
        # id that we replaced in the state.
        if event.is_state():
            prev_state_id = self.prev_state_ids.get((event.type, event.state_key))
        else:
            prev_state_id = None

        return {
            "prev_state_id": prev_state_id,
            "event_type": event.type,
            "event_state_key": event.state_key if event.is_state() else None,
            "state_group": self.state_group,
            "rejected": self.rejected,
            "prev_group": self.prev_group,
            "delta_ids": _encode_state_dict(self.delta_ids),
            "prev_state_events": self.prev_state_events,
            "app_service_id": self.app_service.id if self.app_service else None
        }

    @staticmethod
    @defer.inlineCallbacks
    def deserialize(store, input):
        """Converts a dict that was produced by `serialize` back into a
        EventContext.

        Args:
            store (DataStore): Used to convert AS ID to AS object
            input (dict): A dict produced by `serialize`

        Returns:
            EventContext
        """
        context = EventContext()
        context.state_group = input["state_group"]
        context.rejected = input["rejected"]
        context.prev_group = input["prev_group"]
        context.delta_ids = _decode_state_dict(input["delta_ids"])
        context.prev_state_events = input["prev_state_events"]

        # We use the state_group and prev_state_id stuff to pull the
        # current_state_ids out of the DB and construct prev_state_ids.
        prev_state_id = input["prev_state_id"]
        event_type = input["event_type"]
        event_state_key = input["event_state_key"]

        context.current_state_ids = yield store.get_state_ids_for_group(
            context.state_group,
        )
        if prev_state_id and event_state_key:
            context.prev_state_ids = dict(context.current_state_ids)
            context.prev_state_ids[(event_type, event_state_key)] = prev_state_id
        else:
            context.prev_state_ids = context.current_state_ids

        app_service_id = input["app_service_id"]
        if app_service_id:
            context.app_service = store.get_app_service_by_id(app_service_id)

        defer.returnValue(context)


def _encode_state_dict(state_dict):
    """Since dicts of (type, state_key) -> event_id cannot be serialized in
    JSON we need to convert them to a form that can.
    """
    if state_dict is None:
        return None

    return [
        (etype, state_key, v)
        for (etype, state_key), v in state_dict.iteritems()
    ]


def _decode_state_dict(input):
    """Decodes a state dict encoded using `_encode_state_dict` above
    """
    if input is None:
        return None

    return frozendict({(etype, state_key,): v for etype, state_key, v in input})
