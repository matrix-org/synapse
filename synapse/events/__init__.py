# -*- coding: utf-8 -*-
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
import os
from distutils.util import strtobool
from typing import Dict, Optional, Tuple, Type

from unpaddedbase64 import encode_base64

from synapse.api.room_versions import EventFormatVersions, RoomVersion, RoomVersions
from synapse.types import JsonDict, RoomStreamToken
from synapse.util.caches import intern_dict
from synapse.util.frozenutils import freeze

# Whether we should use frozen_dict in FrozenEvent. Using frozen_dicts prevents
# bugs where we accidentally share e.g. signature dicts. However, converting a
# dict to frozen_dicts is expensive.
#
# NOTE: This is overridden by the configuration by the Synapse worker apps, but
# for the sake of tests, it is set here while it cannot be configured on the
# homeserver object itself.
USE_FROZEN_DICTS = strtobool(os.environ.get("SYNAPSE_USE_FROZEN_DICTS", "0"))


class DictProperty:
    """An object property which delegates to the `_dict` within its parent object."""

    __slots__ = ["key"]

    def __init__(self, key: str):
        self.key = key

    def __get__(self, instance, owner=None):
        # if the property is accessed as a class property rather than an instance
        # property, return the property itself rather than the value
        if instance is None:
            return self
        try:
            return instance._dict[self.key]
        except KeyError as e1:
            # We want this to look like a regular attribute error (mostly so that
            # hasattr() works correctly), so we convert the KeyError into an
            # AttributeError.
            #
            # To exclude the KeyError from the traceback, we explicitly
            # 'raise from e1.__context__' (which is better than 'raise from None',
            # becuase that would omit any *earlier* exceptions).
            #
            raise AttributeError(
                "'%s' has no '%s' property" % (type(instance), self.key)
            ) from e1.__context__

    def __set__(self, instance, v):
        instance._dict[self.key] = v

    def __delete__(self, instance):
        try:
            del instance._dict[self.key]
        except KeyError as e1:
            raise AttributeError(
                "'%s' has no '%s' property" % (type(instance), self.key)
            ) from e1.__context__


class DefaultDictProperty(DictProperty):
    """An extension of DictProperty which provides a default if the property is
    not present in the parent's _dict.

    Note that this means that hasattr() on the property always returns True.
    """

    __slots__ = ["default"]

    def __init__(self, key, default):
        super().__init__(key)
        self.default = default

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        return instance._dict.get(self.key, self.default)


class _EventInternalMetadata:
    __slots__ = ["_dict"]

    def __init__(self, internal_metadata_dict: JsonDict):
        # we have to copy the dict, because it turns out that the same dict is
        # reused. TODO: fix that
        self._dict = dict(internal_metadata_dict)

    outlier = DictProperty("outlier")  # type: bool
    out_of_band_membership = DictProperty("out_of_band_membership")  # type: bool
    send_on_behalf_of = DictProperty("send_on_behalf_of")  # type: str
    recheck_redaction = DictProperty("recheck_redaction")  # type: bool
    soft_failed = DictProperty("soft_failed")  # type: bool
    proactively_send = DictProperty("proactively_send")  # type: bool
    redacted = DictProperty("redacted")  # type: bool
    txn_id = DictProperty("txn_id")  # type: str
    token_id = DictProperty("token_id")  # type: str
    stream_ordering = DictProperty("stream_ordering")  # type: int

    # XXX: These are set by StreamWorkerStore._set_before_and_after.
    # I'm pretty sure that these are never persisted to the database, so shouldn't
    # be here
    before = DictProperty("before")  # type: RoomStreamToken
    after = DictProperty("after")  # type: RoomStreamToken
    order = DictProperty("order")  # type: Tuple[int, int]

    def get_dict(self) -> JsonDict:
        return dict(self._dict)

    def is_outlier(self) -> bool:
        return self._dict.get("outlier", False)

    def is_out_of_band_membership(self) -> bool:
        """Whether this is an out of band membership, like an invite or an invite
        rejection. This is needed as those events are marked as outliers, but
        they still need to be processed as if they're new events (e.g. updating
        invite state in the database, relaying to clients, etc).

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

        Returns:
            bool
        """
        return self._dict.get("recheck_redaction", False)

    def is_soft_failed(self) -> bool:
        """Whether the event has been soft failed.

        Soft failed events should be handled as usual, except:
            1. They should not go down sync or event streams, or generally
               sent to clients.
            2. They should not be added to the forward extremities (and
               therefore not to current state).

        Returns:
            bool
        """
        return self._dict.get("soft_failed", False)

    def should_proactively_send(self):
        """Whether the event, if ours, should be sent to other clients and
        servers.

        This is used for sending dummy events internally. Servers and clients
        can still explicitly fetch the event.

        Returns:
            bool
        """
        return self._dict.get("proactively_send", True)

    def is_redacted(self):
        """Whether the event has been redacted.

        This is used for efficiently checking whether an event has been
        marked as redacted without needing to make another database call.

        Returns:
            bool
        """
        return self._dict.get("redacted", False)


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

    auth_events = DictProperty("auth_events")
    depth = DictProperty("depth")
    content = DictProperty("content")
    hashes = DictProperty("hashes")
    origin = DictProperty("origin")
    origin_server_ts = DictProperty("origin_server_ts")
    prev_events = DictProperty("prev_events")
    redacts = DefaultDictProperty("redacts", None)
    room_id = DictProperty("room_id")
    sender = DictProperty("sender")
    state_key = DictProperty("state_key")
    type = DictProperty("type")
    user_id = DictProperty("sender")

    @property
    def event_id(self) -> str:
        raise NotImplementedError()

    @property
    def membership(self):
        return self.content["membership"]

    def is_state(self):
        return hasattr(self, "state_key") and self.state_key is not None

    def get_dict(self) -> JsonDict:
        d = dict(self._dict)
        d.update({"signatures": self.signatures, "unsigned": dict(self.unsigned)})

        return d

    def get(self, key, default=None):
        return self._dict.get(key, default)

    def get_internal_metadata_dict(self):
        return self.internal_metadata.get_dict()

    def get_pdu_json(self, time_now=None) -> JsonDict:
        pdu_json = self.get_dict()

        if time_now is not None and "age_ts" in pdu_json["unsigned"]:
            age = time_now - pdu_json["unsigned"]["age_ts"]
            pdu_json.setdefault("unsigned", {})["age"] = int(age)
            del pdu_json["unsigned"]["age_ts"]

        # This may be a frozen event
        pdu_json["unsigned"].pop("redacted_because", None)

        return pdu_json

    def __set__(self, instance, value):
        raise AttributeError("Unrecognized attribute %s" % (instance,))

    def __getitem__(self, field):
        return self._dict[field]

    def __contains__(self, field):
        return field in self._dict

    def items(self):
        return list(self._dict.items())

    def keys(self):
        return self._dict.keys()

    def prev_event_ids(self):
        """Returns the list of prev event IDs. The order matches the order
        specified in the event, though there is no meaning to it.

        Returns:
            list[str]: The list of event IDs of this event's prev_events
        """
        return [e for e, _ in self.prev_events]

    def auth_event_ids(self):
        """Returns the list of auth event IDs. The order matches the order
        specified in the event, though there is no meaning to it.

        Returns:
            list[str]: The list of event IDs of this event's auth_events
        """
        return [e for e, _ in self.auth_events]


class FrozenEvent(EventBase):
    format_version = EventFormatVersions.V1  # All events of this type are V1

    def __init__(
        self,
        event_dict: JsonDict,
        room_version: RoomVersion,
        internal_metadata_dict: JsonDict = {},
        rejected_reason: Optional[str] = None,
    ):
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

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<FrozenEvent event_id='%s', type='%s', state_key='%s'>" % (
            self.get("event_id", None),
            self.get("type", None),
            self.get("state_key", None),
        )


class FrozenEventV2(EventBase):
    format_version = EventFormatVersions.V2  # All events of this type are V2

    def __init__(
        self,
        event_dict: JsonDict,
        room_version: RoomVersion,
        internal_metadata_dict: JsonDict = {},
        rejected_reason: Optional[str] = None,
    ):
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

        self._event_id = None

        super().__init__(
            frozen_dict,
            room_version=room_version,
            signatures=signatures,
            unsigned=unsigned,
            internal_metadata_dict=internal_metadata_dict,
            rejected_reason=rejected_reason,
        )

    @property
    def event_id(self):
        # We have to import this here as otherwise we get an import loop which
        # is hard to break.
        from synapse.crypto.event_signing import compute_event_reference_hash

        if self._event_id:
            return self._event_id
        self._event_id = "$" + encode_base64(compute_event_reference_hash(self)[1])
        return self._event_id

    def prev_event_ids(self):
        """Returns the list of prev event IDs. The order matches the order
        specified in the event, though there is no meaning to it.

        Returns:
            list[str]: The list of event IDs of this event's prev_events
        """
        return self.prev_events

    def auth_event_ids(self):
        """Returns the list of auth event IDs. The order matches the order
        specified in the event, though there is no meaning to it.

        Returns:
            list[str]: The list of event IDs of this event's auth_events
        """
        return self.auth_events

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<%s event_id='%s', type='%s', state_key='%s'>" % (
            self.__class__.__name__,
            self.event_id,
            self.get("type", None),
            self.get("state_key", None),
        )


class FrozenEventV3(FrozenEventV2):
    """FrozenEventV3, which differs from FrozenEventV2 only in the event_id format"""

    format_version = EventFormatVersions.V3  # All events of this type are V3

    @property
    def event_id(self):
        # We have to import this here as otherwise we get an import loop which
        # is hard to break.
        from synapse.crypto.event_signing import compute_event_reference_hash

        if self._event_id:
            return self._event_id
        self._event_id = "$" + encode_base64(
            compute_event_reference_hash(self)[1], urlsafe=True
        )
        return self._event_id


def _event_type_from_format_version(format_version: int) -> Type[EventBase]:
    """Returns the python type to use to construct an Event object for the
    given event format version.

    Args:
        format_version (int): The event format version

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
    internal_metadata_dict: JsonDict = {},
    rejected_reason: Optional[str] = None,
) -> EventBase:
    """Construct an EventBase from the given event dict"""
    event_type = _event_type_from_format_version(room_version.event_format)
    return event_type(event_dict, room_version, internal_metadata_dict, rejected_reason)
