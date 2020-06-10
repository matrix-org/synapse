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
from typing import Optional, Union

from six import iteritems

import attr
from frozendict import frozendict

from twisted.internet import defer

from synapse.appservice import ApplicationService
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.types import StateMap


@attr.s(slots=True)
class EventContext:
    """
    Holds information relevant to persisting an event

    Attributes:
        rejected: A rejection reason if the event was rejected, else False

        _state_group: The ID of the state group for this event. Note that state events
            are persisted with a state group which includes the new event, so this is
            effectively the state *after* the event in question.

            For a *rejected* state event, where the state of the rejected event is
            ignored, this state_group should never make it into the
            event_to_state_groups table. Indeed, inspecting this value for a rejected
            state event is almost certainly incorrect.

            For an outlier, where we don't have the state at the event, this will be
            None.

            Note that this is a private attribute: it should be accessed via
            the ``state_group`` property.

        state_group_before_event: The ID of the state group representing the state
            of the room before this event.

            If this is a non-state event, this will be the same as ``state_group``. If
            it's a state event, it will be the same as ``prev_group``.

            If ``state_group`` is None (ie, the event is an outlier),
            ``state_group_before_event`` will always also be ``None``.

        prev_group: If it is known, ``state_group``'s prev_group. Note that this being
            None does not necessarily mean that ``state_group`` does not have
            a prev_group!

            If the event is a state event, this is normally the same as ``prev_group``.

            If ``state_group`` is None (ie, the event is an outlier), ``prev_group``
            will always also be ``None``.

            Note that this *not* (necessarily) the state group associated with
            ``_prev_state_ids``.

        delta_ids: If ``prev_group`` is not None, the state delta between ``prev_group``
            and ``state_group``.

        app_service: If this event is being sent by a (local) application service, that
            app service.

        _current_state_ids: The room state map, including this event - ie, the state
            in ``state_group``.

            (type, state_key) -> event_id

            FIXME: what is this for an outlier? it seems ill-defined. It seems like
            it could be either {}, or the state we were given by the remote
            server, depending on $THINGS

            Note that this is a private attribute: it should be accessed via
            ``get_current_state_ids``. _AsyncEventContext impl calculates this
            on-demand: it will be None until that happens.

        _prev_state_ids: The room state map, excluding this event - ie, the state
            in ``state_group_before_event``. For a non-state
            event, this will be the same as _current_state_events.

            Note that it is a completely different thing to prev_group!

            (type, state_key) -> event_id

            FIXME: again, what is this for an outlier?

            As with _current_state_ids, this is a private attribute. It should be
            accessed via get_prev_state_ids.
    """

    rejected = attr.ib(default=False, type=Union[bool, str])
    _state_group = attr.ib(default=None, type=Optional[int])
    state_group_before_event = attr.ib(default=None, type=Optional[int])
    prev_group = attr.ib(default=None, type=Optional[int])
    delta_ids = attr.ib(default=None, type=Optional[StateMap[str]])
    app_service = attr.ib(default=None, type=Optional[ApplicationService])

    _current_state_ids = attr.ib(default=None, type=Optional[StateMap[str]])
    _prev_state_ids = attr.ib(default=None, type=Optional[StateMap[str]])

    @staticmethod
    def with_state(
        state_group,
        state_group_before_event,
        current_state_ids,
        prev_state_ids,
        prev_group=None,
        delta_ids=None,
    ):
        return EventContext(
            current_state_ids=current_state_ids,
            prev_state_ids=prev_state_ids,
            state_group=state_group,
            state_group_before_event=state_group_before_event,
            prev_group=prev_group,
            delta_ids=delta_ids,
        )

    @defer.inlineCallbacks
    def serialize(self, event, store):
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
            prev_state_ids = yield self.get_prev_state_ids()
            prev_state_id = prev_state_ids.get((event.type, event.state_key))
        else:
            prev_state_id = None

        return {
            "prev_state_id": prev_state_id,
            "event_type": event.type,
            "event_state_key": event.state_key if event.is_state() else None,
            "state_group": self._state_group,
            "state_group_before_event": self.state_group_before_event,
            "rejected": self.rejected,
            "prev_group": self.prev_group,
            "delta_ids": _encode_state_dict(self.delta_ids),
            "app_service_id": self.app_service.id if self.app_service else None,
        }

    @staticmethod
    def deserialize(storage, input):
        """Converts a dict that was produced by `serialize` back into a
        EventContext.

        Args:
            storage (Storage): Used to convert AS ID to AS object and fetch
                state.
            input (dict): A dict produced by `serialize`

        Returns:
            EventContext
        """
        context = _AsyncEventContextImpl(
            # We use the state_group and prev_state_id stuff to pull the
            # current_state_ids out of the DB and construct prev_state_ids.
            storage=storage,
            prev_state_id=input["prev_state_id"],
            event_type=input["event_type"],
            event_state_key=input["event_state_key"],
            state_group=input["state_group"],
            state_group_before_event=input["state_group_before_event"],
            prev_group=input["prev_group"],
            delta_ids=_decode_state_dict(input["delta_ids"]),
            rejected=input["rejected"],
        )

        app_service_id = input["app_service_id"]
        if app_service_id:
            context.app_service = storage.main.get_app_service_by_id(app_service_id)

        return context

    @property
    def state_group(self) -> Optional[int]:
        """The ID of the state group for this event.

        Note that state events are persisted with a state group which includes the new
        event, so this is effectively the state *after* the event in question.

        For an outlier, where we don't have the state at the event, this will be None.

        It is an error to access this for a rejected event, since rejected state should
        not make it into the room state. Accessing this property will raise an exception
        if ``rejected`` is set.
        """
        if self.rejected:
            raise RuntimeError("Attempt to access state_group of rejected event")

        return self._state_group

    @defer.inlineCallbacks
    def get_current_state_ids(self):
        """
        Gets the room state map, including this event - ie, the state in ``state_group``

        It is an error to access this for a rejected event, since rejected state should
        not make it into the room state. This method will raise an exception if
        ``rejected`` is set.

        Returns:
            Deferred[dict[(str, str), str]|None]: Returns None if state_group
                is None, which happens when the associated event is an outlier.

                Maps a (type, state_key) to the event ID of the state event matching
                this tuple.
        """
        if self.rejected:
            raise RuntimeError("Attempt to access state_ids of rejected event")

        yield self._ensure_fetched()
        return self._current_state_ids

    @defer.inlineCallbacks
    def get_prev_state_ids(self):
        """
        Gets the room state map, excluding this event.

        For a non-state event, this will be the same as get_current_state_ids().

        Returns:
            Deferred[dict[(str, str), str]|None]: Returns None if state_group
                is None, which happens when the associated event is an outlier.
                Maps a (type, state_key) to the event ID of the state event matching
                this tuple.
        """
        yield self._ensure_fetched()
        return self._prev_state_ids

    def get_cached_current_state_ids(self):
        """Gets the current state IDs if we have them already cached.

        It is an error to access this for a rejected event, since rejected state should
        not make it into the room state. This method will raise an exception if
        ``rejected`` is set.

        Returns:
            dict[(str, str), str]|None: Returns None if we haven't cached the
            state or if state_group is None, which happens when the associated
            event is an outlier.
        """
        if self.rejected:
            raise RuntimeError("Attempt to access state_ids of rejected event")

        return self._current_state_ids

    def _ensure_fetched(self):
        return defer.succeed(None)


@attr.s(slots=True)
class _AsyncEventContextImpl(EventContext):
    """
    An implementation of EventContext which fetches _current_state_ids and
    _prev_state_ids from the database on demand.

    Attributes:

        _storage (Storage)

        _fetching_state_deferred (Deferred|None): Resolves when *_state_ids have
            been calculated. None if we haven't started calculating yet

        _event_type (str): The type of the event the context is associated with.

        _event_state_key (str): The state_key of the event the context is
            associated with.

        _prev_state_id (str|None): If the event associated with the context is
            a state event, then `_prev_state_id` is the event_id of the state
            that was replaced.
    """

    # This needs to have a default as we're inheriting
    _storage = attr.ib(default=None)
    _prev_state_id = attr.ib(default=None)
    _event_type = attr.ib(default=None)
    _event_state_key = attr.ib(default=None)
    _fetching_state_deferred = attr.ib(default=None)

    def _ensure_fetched(self):
        if not self._fetching_state_deferred:
            self._fetching_state_deferred = run_in_background(self._fill_out_state)

        return make_deferred_yieldable(self._fetching_state_deferred)

    @defer.inlineCallbacks
    def _fill_out_state(self):
        """Called to populate the _current_state_ids and _prev_state_ids
        attributes by loading from the database.
        """
        if self.state_group is None:
            return

        self._current_state_ids = yield self._storage.state.get_state_ids_for_group(
            self.state_group
        )
        if self._event_state_key is not None:
            self._prev_state_ids = dict(self._current_state_ids)

            key = (self._event_type, self._event_state_key)
            if self._prev_state_id:
                self._prev_state_ids[key] = self._prev_state_id
            else:
                self._prev_state_ids.pop(key, None)
        else:
            self._prev_state_ids = self._current_state_ids


def _encode_state_dict(state_dict):
    """Since dicts of (type, state_key) -> event_id cannot be serialized in
    JSON we need to convert them to a form that can.
    """
    if state_dict is None:
        return None

    return [(etype, state_key, v) for (etype, state_key), v in iteritems(state_dict)]


def _decode_state_dict(input):
    """Decodes a state dict encoded using `_encode_state_dict` above
    """
    if input is None:
        return None

    return frozendict({(etype, state_key): v for etype, state_key, v in input})
