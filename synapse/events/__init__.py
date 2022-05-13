# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import collections.abc
import os
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Generic,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

import attr
from typing_extensions import Literal
from unpaddedbase64 import encode_base64

from synapse.api.constants import RelationTypes
from synapse.api.room_versions import EventFormatVersions, RoomVersion, RoomVersions
from synapse.types import JsonDict, RoomStreamToken
from synapse.util.caches import intern_dict
from synapse.util.frozenutils import freeze
from synapse.util.stringutils import strtobool

if TYPE_CHECKING:
    from synapse.events.builder import EventBuilder

# Whether we should use frozen_dict in FrozenEvent. Using frozen_dicts prevents
# bugs where we accidentally share e.g. signature dicts. However, converting a
# dict to frozen_dicts is expensive.
#
# NOTE: This is overridden by the configuration by the Synapse worker apps, but
# for the sake of tests, it is set here while it cannot be configured on the
# homeserver object itself.

USE_FROZEN_DICTS = strtobool(os.environ.get("SYNAPSE_USE_FROZEN_DICTS", "0"))


T = TypeVar("T")


# DictProperty (and DefaultDictProperty) require the classes they're used with to
# have a _dict property to pull properties from.
#
# TODO _DictPropertyInstance should not include EventBuilder but due to
# https://github.com/python/mypy/issues/5570 it thinks the DictProperty and
# DefaultDictProperty get applied to EventBuilder when it is in a Union with
# EventBase. This is the least invasive hack to get mypy to comply.
#
# Note that DictProperty/DefaultDictProperty cannot actually be used with
# EventBuilder as it lacks a _dict property.
_DictPropertyInstance = Union["_EventInternalMetadata", "EventBase", "EventBuilder"]


class DictProperty(Generic[T]):
    """An object property which delegates to the `_dict` within its parent object."""

    __slots__ = ["key"]

    def __init__(self, key: str):
        self.key = key

    @overload
    def __get__(
        self,
        instance: Literal[None],
        owner: Optional[Type[_DictPropertyInstance]] = None,
    ) -> "DictProperty":
        ...

    @overload
    def __get__(
        self,
        instance: _DictPropertyInstance,
        owner: Optional[Type[_DictPropertyInstance]] = None,
    ) -> T:
        ...

    def __get__(
        self,
        instance: Optional[_DictPropertyInstance],
        owner: Optional[Type[_DictPropertyInstance]] = None,
    ) -> Union[T, "DictProperty"]:
        # if the property is accessed as a class property rather than an instance
        # property, return the property itself rather than the value
        if instance is None:
            return self
        try:
            assert isinstance(instance, (EventBase, _EventInternalMetadata))
            return instance._dict[self.key]
        except KeyError as e1:
            # We want this to look like a regular attribute error (mostly so that
            # hasattr() works correctly), so we convert the KeyError into an
            # AttributeError.
            #
            # To exclude the KeyError from the traceback, we explicitly
            # 'raise from e1.__context__' (which is better than 'raise from None',
            # because that would omit any *earlier* exceptions).
            #
            raise AttributeError(
                "'%s' has no '%s' property" % (type(instance), self.key)
            ) from e1.__context__

    def __set__(self, instance: _DictPropertyInstance, v: T) -> None:
        assert isinstance(instance, (EventBase, _EventInternalMetadata))
        instance._dict[self.key] = v

    def __delete__(self, instance: _DictPropertyInstance) -> None:
        assert isinstance(instance, (EventBase, _EventInternalMetadata))
        try:
            del instance._dict[self.key]
        except KeyError as e1:
            raise AttributeError(
                "'%s' has no '%s' property" % (type(instance), self.key)
            ) from e1.__context__


class DefaultDictProperty(DictProperty, Generic[T]):
    """An extension of DictProperty which provides a default if the property is
    not present in the parent's _dict.

    Note that this means that hasattr() on the property always returns True.
    """

    __slots__ = ["default"]

    def __init__(self, key: str, default: T):
        super().__init__(key)
        self.default = default

    @overload
    def __get__(
        self,
        instance: Literal[None],
        owner: Optional[Type[_DictPropertyInstance]] = None,
    ) -> "DefaultDictProperty":
        ...

    @overload
    def __get__(
        self,
        instance: _DictPropertyInstance,
        owner: Optional[Type[_DictPropertyInstance]] = None,
    ) -> T:
        ...

    def __get__(
        self,
        instance: Optional[_DictPropertyInstance],
        owner: Optional[Type[_DictPropertyInstance]] = None,
    ) -> Union[T, "DefaultDictProperty"]:
        if instance is None:
            return self
        assert isinstance(instance, (EventBase, _EventInternalMetadata))
        return instance._dict.get(self.key, self.default)


class _EventInternalMetadata:
    __slots__ = ["_dict", "stream_ordering", "outlier"]

    def __init__(self, internal_metadata_dict: JsonDict):
        # we have to copy the dict, because it turns out that the same dict is
        # reused. TODO: fix that
        self._dict = dict(internal_metadata_dict)

        # the stream ordering of this event. None, until it has been persisted.
        self.stream_ordering: Optional[int] = None

        # whether this event is an outlier (ie, whether we have the state at that point
        # in the DAG)
        self.outlier = False

    out_of_band_membership: DictProperty[bool] = DictProperty("out_of_band_membership")
    send_on_behalf_of: DictProperty[str] = DictProperty("send_on_behalf_of")
    recheck_redaction: DictProperty[bool] = DictProperty("recheck_redaction")
    soft_failed: DictProperty[bool] = DictProperty("soft_failed")
    proactively_send: DictProperty[bool] = DictProperty("proactively_send")
    redacted: DictProperty[bool] = DictProperty("redacted")
    txn_id: DictProperty[str] = DictProperty("txn_id")
    token_id: DictProperty[int] = DictProperty("token_id")
    historical: DictProperty[bool] = DictProperty("historical")

    # XXX: These are set by StreamWorkerStore._set_before_and_after.
    # I'm pretty sure that these are never persisted to the database, so shouldn't
    # be here
    before: DictProperty[RoomStreamToken] = DictProperty("before")
    after: DictProperty[RoomStreamToken] = DictProperty("after")
    order: DictProperty[Tuple[int, int]] = DictProperty("order")

    def get_dict(self) -> JsonDict:
        return dict(self._dict)

    def is_outlier(self) -> bool:
        return self.outlier

    def is_out_of_band_membership(self) -> bool:
        """Whether this event is an out-of-band membership.

        OOB memberships are a special case of outlier events: they are membership events
        for federated rooms that we aren't full members of. Examples include invites
        received over federation, and rejections for such invites.

        The concept of an OOB membership is needed because these events need to be
        processed as if they're new regular events (e.g. updating membership state in
        the database, relaying to clients via /sync, etc) despite being outliers.

        See also https://matrix-org.github.io/synapse/develop/development/room-dag-concepts.html#out-of-band-membership-events.

        (Added in synapse 0.99.0, so may be unreliable for events received before that)
        """
        return self._dict.get("out_of_band_membership", False)

    def get_send_on_behalf_of(self) -> Optional[str]:
        """Whether this server should send the event on behalf of another server.
        This is used by the federation "send_join" API to forward the initial join
        event for a server in the room.

        returns a str with the name of the server this event is sent on behalf of.
        """
        return self._dict.get("send_on_behalf_of")

    def need_to_check_redaction(self) -> bool:
        """Whether the redaction event needs to be rechecked when fetching
        from the database.

        Starting in room v3 redaction events are accepted up front, and later
        checked to see if the redacter and redactee's domains match.

        If the sender of the redaction event is allowed to redact any event
        due to auth rules, then this will always return false.
        """
        return self._dict.get("recheck_redaction", False)

    def is_soft_failed(self) -> bool:
        """Whether the event has been soft failed.

        Soft failed events should be handled as usual, except:
            1. They should not go down sync or event streams, or generally
               sent to clients.
            2. They should not be added to the forward extremities (and
               therefore not to current state).
        """
        return self._dict.get("soft_failed", False)

    def should_proactively_send(self) -> bool:
        """Whether the event, if ours, should be sent to other clients and
        servers.

        This is used for sending dummy events internally. Servers and clients
        can still explicitly fetch the event.
        """
        return self._dict.get("proactively_send", True)

    def is_redacted(self) -> bool:
        """Whether the event has been redacted.

        This is used for efficiently checking whether an event has been
        marked as redacted without needing to make another database call.
        """
        return self._dict.get("redacted", False)

    def is_historical(self) -> bool:
        """Whether this is a historical message.
        This is used by the batchsend historical message endpoint and
        is needed to and mark the event as backfilled and skip some checks
        like push notifications.
        """
        return self._dict.get("historical", False)


class EventBase(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def format_version(self) -> int:
        """The EventFormatVersion implemented by this event"""
        ...

    def __init__(
        self,
        event_dict: JsonDict,
        room_version: RoomVersion,
        signatures: Dict[str, Dict[str, str]],
        unsigned: JsonDict,
        internal_metadata_dict: JsonDict,
        rejected_reason: Optional[str],
    ):
        assert room_version.event_format == self.format_version

        self.room_version = room_version
        self.signatures = signatures
        self.unsigned = unsigned
        self.rejected_reason = rejected_reason

        self._dict = event_dict

        self.internal_metadata = _EventInternalMetadata(internal_metadata_dict)

    depth: DictProperty[int] = DictProperty("depth")
    content: DictProperty[JsonDict] = DictProperty("content")
    hashes: DictProperty[Dict[str, str]] = DictProperty("hashes")
    origin: DictProperty[str] = DictProperty("origin")
    origin_server_ts: DictProperty[int] = DictProperty("origin_server_ts")
    redacts: DefaultDictProperty[Optional[str]] = DefaultDictProperty("redacts", None)
    room_id: DictProperty[str] = DictProperty("room_id")
    sender: DictProperty[str] = DictProperty("sender")
    # TODO state_key should be Optional[str]. This is generally asserted in Synapse
    # by calling is_state() first (which ensures it is not None), but it is hard (not possible?)
    # to properly annotate that calling is_state() asserts that state_key exists
    # and is non-None. It would be better to replace such direct references with
    # get_state_key() (and a check for None).
    state_key: DictProperty[str] = DictProperty("state_key")
    type: DictProperty[str] = DictProperty("type")
    user_id: DictProperty[str] = DictProperty("sender")

    @property
    def event_id(self) -> str:
        raise NotImplementedError()

    @property
    def membership(self) -> str:
        return self.content["membership"]

    def is_state(self) -> bool:
        return self.get_state_key() is not None

    def get_state_key(self) -> Optional[str]:
        """Get the state key of this event, or None if it's not a state event"""
        return self._dict.get("state_key")

    def get_dict(self) -> JsonDict:
        d = dict(self._dict)
        d.update({"signatures": self.signatures, "unsigned": dict(self.unsigned)})

        return d

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        return self._dict.get(key, default)

    def get_internal_metadata_dict(self) -> JsonDict:
        return self.internal_metadata.get_dict()

    def get_pdu_json(self, time_now: Optional[int] = None) -> JsonDict:
        pdu_json = self.get_dict()

        if time_now is not None and "age_ts" in pdu_json["unsigned"]:
            age = time_now - pdu_json["unsigned"]["age_ts"]
            pdu_json.setdefault("unsigned", {})["age"] = int(age)
            del pdu_json["unsigned"]["age_ts"]

        # This may be a frozen event
        pdu_json["unsigned"].pop("redacted_because", None)

        return pdu_json

    def get_templated_pdu_json(self) -> JsonDict:
        """
        Return a JSON object suitable for a templated event, as used in the
        make_{join,leave,knock} workflow.
        """
        # By using _dict directly we don't pull in signatures/unsigned.
        template_json = dict(self._dict)
        # The hashes (similar to the signature) need to be recalculated by the
        # joining/leaving/knocking server after (potentially) modifying the
        # event.
        template_json.pop("hashes")

        return template_json

    def __getitem__(self, field: str) -> Optional[Any]:
        return self._dict[field]

    def __contains__(self, field: str) -> bool:
        return field in self._dict

    def items(self) -> List[Tuple[str, Optional[Any]]]:
        return list(self._dict.items())

    def keys(self) -> Iterable[str]:
        return self._dict.keys()

    def prev_event_ids(self) -> Sequence[str]:
        """Returns the list of prev event IDs. The order matches the order
        specified in the event, though there is no meaning to it.

        Returns:
            The list of event IDs of this event's prev_events
        """
        return [e for e, _ in self._dict["prev_events"]]

    def auth_event_ids(self) -> Sequence[str]:
        """Returns the list of auth event IDs. The order matches the order
        specified in the event, though there is no meaning to it.

        Returns:
            The list of event IDs of this event's auth_events
        """
        return [e for e, _ in self._dict["auth_events"]]

    def freeze(self) -> None:
        """'Freeze' the event dict, so it cannot be modified by accident"""

        # this will be a no-op if the event dict is already frozen.
        self._dict = freeze(self._dict)

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        rejection = f"REJECTED={self.rejected_reason}, " if self.rejected_reason else ""

        return (
            f"<{self.__class__.__name__} "
            f"{rejection}"
            f"event_id={self.event_id}, "
            f"type={self.get('type')}, "
            f"state_key={self.get('state_key')}, "
            f"outlier={self.internal_metadata.is_outlier()}"
            ">"
        )


class FrozenEvent(EventBase):
    format_version = EventFormatVersions.V1  # All events of this type are V1

    def __init__(
        self,
        event_dict: JsonDict,
        room_version: RoomVersion,
        internal_metadata_dict: Optional[JsonDict] = None,
        rejected_reason: Optional[str] = None,
    ):
        internal_metadata_dict = internal_metadata_dict or {}

        event_dict = dict(event_dict)

        # Signatures is a dict of dicts, and this is faster than doing a
        # copy.deepcopy
        signatures = {
            name: {sig_id: sig for sig_id, sig in sigs.items()}
            for name, sigs in event_dict.pop("signatures", {}).items()
        }

        unsigned = dict(event_dict.pop("unsigned", {}))

        # We intern these strings because they turn up a lot (especially when
        # caching).
        event_dict = intern_dict(event_dict)

        if USE_FROZEN_DICTS:
            frozen_dict = freeze(event_dict)
        else:
            frozen_dict = event_dict

        self._event_id = event_dict["event_id"]

        super().__init__(
            frozen_dict,
            room_version=room_version,
            signatures=signatures,
            unsigned=unsigned,
            internal_metadata_dict=internal_metadata_dict,
            rejected_reason=rejected_reason,
        )

    @property
    def event_id(self) -> str:
        return self._event_id


class FrozenEventV2(EventBase):
    format_version = EventFormatVersions.V2  # All events of this type are V2

    def __init__(
        self,
        event_dict: JsonDict,
        room_version: RoomVersion,
        internal_metadata_dict: Optional[JsonDict] = None,
        rejected_reason: Optional[str] = None,
    ):
        internal_metadata_dict = internal_metadata_dict or {}

        event_dict = dict(event_dict)

        # Signatures is a dict of dicts, and this is faster than doing a
        # copy.deepcopy
        signatures = {
            name: {sig_id: sig for sig_id, sig in sigs.items()}
            for name, sigs in event_dict.pop("signatures", {}).items()
        }

        assert "event_id" not in event_dict

        unsigned = dict(event_dict.pop("unsigned", {}))

        # We intern these strings because they turn up a lot (especially when
        # caching).
        event_dict = intern_dict(event_dict)

        if USE_FROZEN_DICTS:
            frozen_dict = freeze(event_dict)
        else:
            frozen_dict = event_dict

        self._event_id: Optional[str] = None

        super().__init__(
            frozen_dict,
            room_version=room_version,
            signatures=signatures,
            unsigned=unsigned,
            internal_metadata_dict=internal_metadata_dict,
            rejected_reason=rejected_reason,
        )

    @property
    def event_id(self) -> str:
        # We have to import this here as otherwise we get an import loop which
        # is hard to break.
        from synapse.crypto.event_signing import compute_event_reference_hash

        if self._event_id:
            return self._event_id
        self._event_id = "$" + encode_base64(compute_event_reference_hash(self)[1])
        return self._event_id

    def prev_event_ids(self) -> Sequence[str]:
        """Returns the list of prev event IDs. The order matches the order
        specified in the event, though there is no meaning to it.

        Returns:
            The list of event IDs of this event's prev_events
        """
        return self._dict["prev_events"]

    def auth_event_ids(self) -> Sequence[str]:
        """Returns the list of auth event IDs. The order matches the order
        specified in the event, though there is no meaning to it.

        Returns:
            The list of event IDs of this event's auth_events
        """
        return self._dict["auth_events"]


class FrozenEventV3(FrozenEventV2):
    """FrozenEventV3, which differs from FrozenEventV2 only in the event_id format"""

    format_version = EventFormatVersions.V3  # All events of this type are V3

    @property
    def event_id(self) -> str:
        # We have to import this here as otherwise we get an import loop which
        # is hard to break.
        from synapse.crypto.event_signing import compute_event_reference_hash

        if self._event_id:
            return self._event_id
        self._event_id = "$" + encode_base64(
            compute_event_reference_hash(self)[1], urlsafe=True
        )
        return self._event_id


def _event_type_from_format_version(
    format_version: int,
) -> Type[Union[FrozenEvent, FrozenEventV2, FrozenEventV3]]:
    """Returns the python type to use to construct an Event object for the
    given event format version.

    Args:
        format_version: The event format version

    Returns:
        type: A type that can be initialized as per the initializer of
        `FrozenEvent`
    """

    if format_version == EventFormatVersions.V1:
        return FrozenEvent
    elif format_version == EventFormatVersions.V2:
        return FrozenEventV2
    elif format_version == EventFormatVersions.V3:
        return FrozenEventV3
    else:
        raise Exception("No event format %r" % (format_version,))


def make_event_from_dict(
    event_dict: JsonDict,
    room_version: RoomVersion = RoomVersions.V1,
    internal_metadata_dict: Optional[JsonDict] = None,
    rejected_reason: Optional[str] = None,
) -> EventBase:
    """Construct an EventBase from the given event dict"""
    event_type = _event_type_from_format_version(room_version.event_format)
    return event_type(
        event_dict, room_version, internal_metadata_dict or {}, rejected_reason
    )


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _EventRelation:
    # The target event of the relation.
    parent_id: str
    # The relation type.
    rel_type: str
    # The aggregation key. Will be None if the rel_type is not m.annotation or is
    # not a string.
    aggregation_key: Optional[str]


def relation_from_event(event: EventBase) -> Optional[_EventRelation]:
    """
    Attempt to parse relation information an event.

    Returns:
        The event relation information, if it is valid. None, otherwise.
    """
    relation = event.content.get("m.relates_to")
    if not relation or not isinstance(relation, collections.abc.Mapping):
        # No relation information.
        return None

    # Relations must have a type and parent event ID.
    rel_type = relation.get("rel_type")
    if not isinstance(rel_type, str):
        return None

    parent_id = relation.get("event_id")
    if not isinstance(parent_id, str):
        return None

    # Annotations have a key field.
    aggregation_key = None
    if rel_type == RelationTypes.ANNOTATION:
        aggregation_key = relation.get("key")
        if not isinstance(aggregation_key, str):
            aggregation_key = None

    return _EventRelation(parent_id, rel_type, aggregation_key)
