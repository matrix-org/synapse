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
from typing import TYPE_CHECKING, List, Optional, Tuple, Union

import attr
from frozendict import frozendict

from twisted.internet.defer import Deferred

from synapse.appservice import ApplicationService
from synapse.events import EventBase
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.types import JsonDict, StateMap

if TYPE_CHECKING:
    from synapse.storage import Storage
    from synapse.storage.databases.main import DataStore


@attr.s(slots=True, auto_attribs=True)
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

            For an outlier, this is {}

            Note that this is a private attribute: it should be accessed via
            ``get_current_state_ids``. _AsyncEventContext impl calculates this
            on-demand: it will be None until that happens.

        _prev_state_ids: The room state map, excluding this event - ie, the state
            in ``state_group_before_event``. For a non-state
            event, this will be the same as _current_state_events.

            Note that it is a completely different thing to prev_group!

            (type, state_key) -> event_id

            For an outlier, this is {}

            As with _current_state_ids, this is a private attribute. It should be
            accessed via get_prev_state_ids.

        partial_state: if True, we may be storing this event with a temporary,
            incomplete state.
    """

    rejected: Union[bool, str] = False
    _state_group: Optional[int] = None
    state_group_before_event: Optional[int] = None
    prev_group: Optional[int] = None
    delta_ids: Optional[StateMap[str]] = None
    app_service: Optional[ApplicationService] = None

    _current_state_ids: Optional[StateMap[str]] = None
    _prev_state_ids: Optional[StateMap[str]] = None

    partial_state: bool = False

    @staticmethod
    def with_state(
        state_group: Optional[int],
        state_group_before_event: Optional[int],
        current_state_ids: Optional[StateMap[str]],
        prev_state_ids: Optional[StateMap[str]],
        partial_state: bool,
        prev_group: Optional[int] = None,
        delta_ids: Optional[StateMap[str]] = None,
    ) -> "EventContext":
        return EventContext(
            current_state_ids=current_state_ids,
            prev_state_ids=prev_state_ids,
            state_group=state_group,
            state_group_before_event=state_group_before_event,
            prev_group=prev_group,
            delta_ids=delta_ids,
            partial_state=partial_state,
        )

    @staticmethod
    def for_outlier() -> "EventContext":
        """Return an EventContext instance suitable for persisting an outlier event"""
        return EventContext(
            current_state_ids={},
            prev_state_ids={},
        )

    async def serialize(self, event: EventBase, store: "DataStore") -> JsonDict:
        """Converts self to a type that can be serialized as JSON, and then
        deserialized by `deserialize`

        Args:
            event: The event that this context relates to

        Returns:
            The serialized event.
        """

        # We don't serialize the full state dicts, instead they get pulled out
        # of the DB on the other side. However, the other side can't figure out
        # the prev_state_ids, so if we're a state event we include the event
        # id that we replaced in the state.
        if event.is_state():
            prev_state_ids = await self.get_prev_state_ids()
            prev_state_id = prev_state_ids.get((event.type, event.state_key))
        else:
            prev_state_id = None

        return {
            "prev_state_id": prev_state_id,
            "event_type": event.type,
            "event_state_key": event.get_state_key(),
            "state_group": self._state_group,
            "state_group_before_event": self.state_group_before_event,
            "rejected": self.rejected,
            "prev_group": self.prev_group,
            "delta_ids": _encode_state_dict(self.delta_ids),
            "app_service_id": self.app_service.id if self.app_service else None,
            "partial_state": self.partial_state,
        }

    @staticmethod
    def deserialize(storage: "Storage", input: JsonDict) -> "EventContext":
        """Converts a dict that was produced by `serialize` back into a
        EventContext.

        Args:
            storage: Used to convert AS ID to AS object and fetch state.
            input: A dict produced by `serialize`

        Returns:
            The event context.
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
            partial_state=input.get("partial_state", False),
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

    async def get_current_state_ids(self) -> Optional[StateMap[str]]:
        """
        Gets the room state map, including this event - ie, the state in ``state_group``

        It is an error to access this for a rejected event, since rejected state should
        not make it into the room state. This method will raise an exception if
        ``rejected`` is set.

        Returns:
            Returns None if state_group is None, which happens when the associated
            event is an outlier.

            Maps a (type, state_key) to the event ID of the state event matching
            this tuple.
        """
        if self.rejected:
            raise RuntimeError("Attempt to access state_ids of rejected event")

        await self._ensure_fetched()
        return self._current_state_ids

    async def get_prev_state_ids(self) -> StateMap[str]:
        """
        Gets the room state map, excluding this event.

        For a non-state event, this will be the same as get_current_state_ids().

        Returns:
            Returns {} if state_group is None, which happens when the associated
            event is an outlier.

            Maps a (type, state_key) to the event ID of the state event matching
            this tuple.
        """
        await self._ensure_fetched()
        # There *should* be previous state IDs now.
        assert self._prev_state_ids is not None
        return self._prev_state_ids

    def get_cached_current_state_ids(self) -> Optional[StateMap[str]]:
        """Gets the current state IDs if we have them already cached.

        It is an error to access this for a rejected event, since rejected state should
        not make it into the room state. This method will raise an exception if
        ``rejected`` is set.

        Returns:
            Returns None if we haven't cached the state or if state_group is None
            (which happens when the associated event is an outlier).

            Otherwise, returns the the current state IDs.
        """
        if self.rejected:
            raise RuntimeError("Attempt to access state_ids of rejected event")

        return self._current_state_ids

    async def _ensure_fetched(self) -> None:
        return None


@attr.s(slots=True)
class _AsyncEventContextImpl(EventContext):
    """
    An implementation of EventContext which fetches _current_state_ids and
    _prev_state_ids from the database on demand.

    Attributes:

        _storage

        _fetching_state_deferred: Resolves when *_state_ids have been calculated.
            None if we haven't started calculating yet

        _event_type: The type of the event the context is associated with.

        _event_state_key: The state_key of the event the context is associated with.

        _prev_state_id: If the event associated with the context is a state event,
            then `_prev_state_id` is the event_id of the state that was replaced.
    """

    # This needs to have a default as we're inheriting
    _storage: "Storage" = attr.ib(default=None)
    _prev_state_id: Optional[str] = attr.ib(default=None)
    _event_type: str = attr.ib(default=None)
    _event_state_key: Optional[str] = attr.ib(default=None)
    _fetching_state_deferred: Optional["Deferred[None]"] = attr.ib(default=None)

    async def _ensure_fetched(self) -> None:
        if not self._fetching_state_deferred:
            self._fetching_state_deferred = run_in_background(self._fill_out_state)

        await make_deferred_yieldable(self._fetching_state_deferred)

    async def _fill_out_state(self) -> None:
        """Called to populate the _current_state_ids and _prev_state_ids
        attributes by loading from the database.
        """
        if self.state_group is None:
            # No state group means the event is an outlier. Usually the state_ids dicts are also
            # pre-set to empty dicts, but they get reset when the context is serialized, so set
            # them to empty dicts again here.
            self._current_state_ids = {}
            self._prev_state_ids = {}
            return

        current_state_ids = await self._storage.state.get_state_ids_for_group(
            self.state_group
        )
        # Set this separately so mypy knows current_state_ids is not None.
        self._current_state_ids = current_state_ids
        if self._event_state_key is not None:
            self._prev_state_ids = dict(current_state_ids)

            key = (self._event_type, self._event_state_key)
            if self._prev_state_id:
                self._prev_state_ids[key] = self._prev_state_id
            else:
                self._prev_state_ids.pop(key, None)
        else:
            self._prev_state_ids = current_state_ids


def _encode_state_dict(
    state_dict: Optional[StateMap[str]],
) -> Optional[List[Tuple[str, str, str]]]:
    """Since dicts of (type, state_key) -> event_id cannot be serialized in
    JSON we need to convert them to a form that can.
    """
    if state_dict is None:
        return None

    return [(etype, state_key, v) for (etype, state_key), v in state_dict.items()]


def _decode_state_dict(
    input: Optional[List[Tuple[str, str, str]]]
) -> Optional[StateMap[str]]:
    """Decodes a state dict encoded using `_encode_state_dict` above"""
    if input is None:
        return None

    return frozendict({(etype, state_key): v for etype, state_key, v in input})
