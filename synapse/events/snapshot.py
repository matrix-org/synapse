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

import abc

from frozendict import frozendict

from twisted.internet import defer


class StatelessContext(object):
    """
    Attributes:
        state_group (int|None): state group id, if the state has been stored
            as a state group. This is usually only None if e.g. the event is
            an outlier.
        rejected (bool|str): A rejection reason if the event was rejected, else
            False

        prev_group (int): Previously persisted state group. ``None`` for an
            outlier.
        delta_ids (dict[(str, str), str]): Delta from ``prev_group``.
            (type, state_key) -> event_id. ``None`` for an outlier.

        prev_state_events (?): XXX: is this ever set to anything other than
            the empty list?

        current_state_ids (dict[(str, str), str]|None):
            The current state map including the current event.
            (type, state_key) -> event_id

        prev_state_ids (dict[(str, str), str]|None):
            The current state map excluding the current event.
            (type, state_key) -> event_id
    """

    __metaclass__ = abc.ABCMeta

    __slots__ = [
        "state_group",
        "rejected",
        "prev_group",
        "delta_ids",
        "prev_state_events",
        "app_service",

        "current_state_ids",
        "prev_state_ids",
    ]

    def __init__(self):
        self.state_group = None

        self.rejected = False

        # A previously persisted state group and a delta between that
        # and this state.
        self.prev_group = None
        self.delta_ids = None

        self.prev_state_events = None

        self.app_service = None

        # The current state including the current event
        self.current_state_ids = None
        # The current state excluding the current event
        self.prev_state_ids = None

    @abc.abstractmethod
    def get_current_state_ids(self, store):
        """Gets the current state IDs

        Returns:
            Deferred[dict[(str, str), str]|None]
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_prev_state_ids(self, store):
        """Gets the prev state IDs

        Returns:
            Deferred[dict[(str, str), str]|None]
        """
        raise NotImplementedError()


class EventContext(StatelessContext):
    """This is the same as StatelessContext, except guarantees that
    current_state_ids and prev_state_ids are set.
    """
    __slots__ = []

    def serialize(self, event):
        """Converts self to a type that can be serialized as JSON, and then
        deserialized by `DeserializedContext.deserialize`

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

    def get_current_state_ids(self, store):
        """Implements StatelessContext"""
        return defer.succeed(self.current_state_ids)

    def get_prev_state_ids(self, store):
        """Implements StatelessContext"""
        return defer.succeed(self.prev_state_ids)


class DeserializedContext(StatelessContext):
    """A context that comes from a serialized version of a StatelessContext.

    It does not necessarily have current_state_ids and prev_state_ids filled
    out (unlike EventContext), but does cache the results of
    `get_current_state_ids` and `get_prev_state_ids`.

    Attributes:
        _have_fetched_state (bool): Whether we attempted to fill out
            current_state_ids
        _prev_state_id (str|None): If set then the event associated with the
            context overrode the _prev_state_id
        _event_type (str): The type of the event the context is associated with
        _event_state_key (str|None): The state_key of the event the context is
            associated with
    """

    __slots__ = [
        "_have_fetched_state",
        "_prev_state_id",
        "_event_type",
        "_event_state_key",
    ]

    @staticmethod
    def deserialize(store, input):
        """Converts a dict that was produced by `serialize` back into a
        StatelessContext.

        Args:
            store (DataStore): Used to convert AS ID to AS object
            input (dict): A dict produced by `serialize`

        Returns:
            StatelessContext
        """
        context = DeserializedContext()
        context.state_group = input["state_group"]
        context.rejected = input["rejected"]
        context.prev_group = input["prev_group"]
        context.delta_ids = _decode_state_dict(input["delta_ids"])
        context.prev_state_events = input["prev_state_events"]

        # We use the state_group and prev_state_id stuff to pull the
        # current_state_ids out of the DB and construct prev_state_ids.
        context._prev_state_id = input["prev_state_id"]
        context._event_type = input["event_type"]
        context._event_state_key = input["event_state_key"]

        context._have_fetched_state = False

        app_service_id = input["app_service_id"]
        if app_service_id:
            context.app_service = store.get_app_service_by_id(app_service_id)

        return context

    @defer.inlineCallbacks
    def get_current_state_ids(self, store):
        """Implements StatelessContext"""

        if not self._have_fetched_state:
            yield self._fill_out_state(store)

        defer.returnValue(self.current_state_ids)

    @defer.inlineCallbacks
    def get_prev_state_ids(self, store):
        """Implements StatelessContext"""

        if not self._have_fetched_state:
            yield self._fill_out_state(store)

        defer.returnValue(self.current_state_ids)

    @defer.inlineCallbacks
    def _fill_out_state(self, store):
        """Called to populate the current_state_ids and prev_state_ids
        attributes by loading from the database.
        """
        self._have_fetched_state = True

        if self.state_group is None:
            return

        self.current_state_ids = yield store.get_state_ids_for_group(
            self.state_group,
        )
        if self._prev_state_id:
            self.prev_state_ids = dict(self.current_state_ids)

            key = (self._event_type, self._event_state_key)
            self.prev_state_ids[key] = self._prev_state_id
        else:
            self.prev_state_ids = self.current_state_ids


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
