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
import zlib
from typing import Dict, List, Optional, Tuple, Type, Union

import attr
from unpaddedbase64 import decode_base64, encode_base64

from synapse.api.room_versions import EventFormatVersions, RoomVersion, RoomVersions
from synapse.types import JsonDict, RoomStreamToken
from synapse.util import json_decoder, json_encoder
from synapse.util.caches import intern_dict
from synapse.util.frozenutils import freeze
from synapse.util.stringutils import strtobool

# Whether we should use frozen_dict in FrozenEvent. Using frozen_dicts prevents
# bugs where we accidentally share e.g. signature dicts. However, converting a
# dict to frozen_dicts is expensive.
#
# NOTE: This is overridden by the configuration by the Synapse worker apps, but
# for the sake of tests, it is set here while it cannot be configured on the
# homeserver object itself.

USE_FROZEN_DICTS = strtobool(os.environ.get("SYNAPSE_USE_FROZEN_DICTS", "0"))


_PRESET_ZDICT = b"""{"auth_events":[],"prev_events":[],"type":"m.room.member",m.room.message"room_id":,"sender":,"content":{"msgtype":"m.text","body":""room_version":"creator":"depth":"prev_state":"state_key":""origin":"origin_server_ts":"hashes":{"sha256":"signatures":,"unsigned":{"age_ts":"ed25519"""


def _encode_dict(d: JsonDict) -> bytes:
    json_bytes = json_encoder.encode(d).encode("utf-8")
    c = zlib.compressobj(1, zdict=_PRESET_ZDICT)
    result_bytes = c.compress(json_bytes)
    result_bytes += c.flush()
    return result_bytes


def _decode_dict(b: bytes) -> JsonDict:
    d = zlib.decompressobj(zdict=_PRESET_ZDICT)

    result_bytes = d.decompress(b)
    result_bytes += d.flush()

    return json_decoder.decode(result_bytes.decode("utf-8"))


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
            # because that would omit any *earlier* exceptions).
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
    __slots__ = ["_dict", "stream_ordering", "outlier"]

    def __init__(self, internal_metadata_dict: JsonDict):
        # we have to copy the dict, because it turns out that the same dict is
        # reused. TODO: fix that
        self._dict = dict(internal_metadata_dict)

        # the stream ordering of this event. None, until it has been persisted.
        self.stream_ordering = None  # type: Optional[int]

        # whether this event is an outlier (ie, whether we have the state at that point
        # in the DAG)
        self.outlier = False

    out_of_band_membership = DictProperty("out_of_band_membership")  # type: bool
    send_on_behalf_of = DictProperty("send_on_behalf_of")  # type: str
    recheck_redaction = DictProperty("recheck_redaction")  # type: bool
    soft_failed = DictProperty("soft_failed")  # type: bool
    proactively_send = DictProperty("proactively_send")  # type: bool
    redacted = DictProperty("redacted")  # type: bool
    txn_id = DictProperty("txn_id")  # type: str
    token_id = DictProperty("token_id")  # type: str

    # XXX: These are set by StreamWorkerStore._set_before_and_after.
    # I'm pretty sure that these are never persisted to the database, so shouldn't
    # be here
    before = DictProperty("before")  # type: RoomStreamToken
    after = DictProperty("after")  # type: RoomStreamToken
    order = DictProperty("order")  # type: Tuple[int, int]

    def get_dict(self) -> JsonDict:
        return dict(self._dict)

    def is_outlier(self) -> bool:
        return self.outlier

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


@attr.s(slots=True, auto_attribs=True)
class _Signatures:
    _signatures_bytes: bytes

    @staticmethod
    def from_dict(signature_dict: JsonDict) -> "_Signatures":
        return _Signatures(_encode_dict(signature_dict))

    def get_dict(self) -> JsonDict:
        return _decode_dict(self._signatures_bytes)

    def get(self, server_name, default=None):
        return self.get_dict().get(server_name, default)

    def update(self, other: Union[JsonDict, "_Signatures"]):
        if isinstance(other, _Signatures):
            other_dict = _decode_dict(other._signatures_bytes)
        else:
            other_dict = other

        signatures = self.get_dict()
        signatures.update(other_dict)
        self._signatures_bytes = _encode_dict(signatures)


class _SmallListV1(str):
    __slots__ = []

    def get(self):
        return self.split(",")

    @staticmethod
    def create(event_ids):
        return _SmallListV1(",".join(event_ids))


class _SmallListV2_V3(bytes):
    __slots__ = []

    def get(self, url_safe):
        i = 0
        while i * 32 < len(self):
            bit = self[i * 32 : (i + 1) * 32]
            i += 1
            yield "$" + encode_base64(bit, urlsafe=url_safe)

    @staticmethod
    def create(event_ids):
        return _SmallListV2_V3(
            b"".join(decode_base64(event_id[1:]) for event_id in event_ids)
        )


class EventBase(metaclass=abc.ABCMeta):
    __slots__ = [
        "room_version",
        "signatures",
        "unsigned",
        "rejected_reason",
        "_encoded_dict",
        "_auth_event_ids",
        "depth",
        "_content",
        "_hashes",
        "origin",
        "origin_server_ts",
        "_prev_event_ids",
        "redacts",
        "room_id",
        "sender",
        "type",
        "state_key",
        "internal_metadata",
    ]

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
        self.signatures = _Signatures.from_dict(signatures)
        self.unsigned = unsigned
        self.rejected_reason = rejected_reason

        self._encoded_dict = _encode_dict(event_dict)

        self.depth = event_dict["depth"]
        self.origin = event_dict.get("origin")
        self.origin_server_ts = event_dict["origin_server_ts"]
        self.redacts = event_dict.get("redacts")
        self.room_id = event_dict["room_id"]
        self.sender = event_dict["sender"]
        self.type = event_dict["type"]
        if "state_key" in event_dict:
            self.state_key = event_dict["state_key"]

        self.internal_metadata = _EventInternalMetadata(internal_metadata_dict)

    @property
    def content(self) -> JsonDict:
        return self.get_dict()["content"]

    @property
    def hashes(self) -> JsonDict:
        return self.get_dict()["hashes"]

    @property
    def prev_events(self) -> List[str]:
        return list(self._prev_events)

    @property
    def event_id(self) -> str:
        raise NotImplementedError()

    @property
    def user_id(self) -> str:
        return self.sender

    @property
    def membership(self):
        return self.content["membership"]

    def is_state(self):
        return hasattr(self, "state_key") and self.state_key is not None

    def get_dict(self) -> JsonDict:
        d = _decode_dict(self._encoded_dict)
        d.update(
            {"signatures": self.signatures.get_dict(), "unsigned": dict(self.unsigned)}
        )

        return d

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

    def freeze(self):
        """'Freeze' the event dict, so it cannot be modified by accident"""

        # this will be a no-op if the event dict is already frozen.
        # self._dict = freeze(self._dict)


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
        self._auth_event_ids = _SmallListV1.create(
            e for e, _ in event_dict["auth_events"]
        )
        self._prev_event_ids = _SmallListV1.create(
            e for e, _ in event_dict["prev_events"]
        )

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

    def auth_event_ids(self):
        return list(self._auth_event_ids.get())

    def prev_event_ids(self):
        return list(self._prev_event_ids.get())

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<FrozenEvent event_id=%r, type=%r, state_key=%r>" % (
            self.event_id,
            self.type,
            getattr(self, "state_key", None),
        )


class FrozenEventV2(EventBase):
    __slots__ = ["_event_id"]

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

        self._event_id = None
        self._auth_event_ids = _SmallListV2_V3.create(event_dict["auth_events"])
        self._prev_event_ids = _SmallListV2_V3.create(event_dict["prev_events"])

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

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<%s event_id=%r, type=%r, state_key=%r>" % (
            self.__class__.__name__,
            self.event_id,
            self.type,
            self.state_key if self.is_state() else None,
        )

    def auth_event_ids(self):
        return list(self._auth_event_ids.get(False))

    def prev_event_ids(self):
        return list(self._prev_event_ids.get(False))


class FrozenEventV3(FrozenEventV2):
    """FrozenEventV3, which differs from FrozenEventV2 only in the event_id format"""

    __slots__ = ["_event_id"]

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

    def auth_event_ids(self):
        return list(self._auth_event_ids.get(True))

    def prev_event_ids(self):
        return list(self._prev_event_ids.get(True))


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
    internal_metadata_dict: Optional[JsonDict] = None,
    rejected_reason: Optional[str] = None,
) -> EventBase:
    """Construct an EventBase from the given event dict"""
    event_type = _event_type_from_format_version(room_version.event_format)
    return event_type(
        event_dict, room_version, internal_metadata_dict or {}, rejected_reason
    )
