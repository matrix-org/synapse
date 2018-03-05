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

from synapse.util.frozenutils import freeze, unfreeze
from synapse.util.caches import intern_dict, intern_string

import abc
import simplejson as json


# Whether we should use frozen_dict in FrozenEvent. Using frozen_dicts prevents
# bugs where we accidentally share e.g. signature dicts. However, converting
# a dict to frozen_dicts is expensive.
USE_FROZEN_DICTS = True


class _EventInternalMetadata(object):
    def __init__(self, internal_metadata_dict):
        self.__dict__ = dict(internal_metadata_dict)

    def get_dict(self):
        return dict(self.__dict__)

    def is_outlier(self):
        return getattr(self, "outlier", False)

    def is_invite_from_remote(self):
        return getattr(self, "invite_from_remote", False)

    def get_send_on_behalf_of(self):
        """Whether this server should send the event on behalf of another server.
        This is used by the federation "send_join" API to forward the initial join
        event for a server in the room.

        returns a str with the name of the server this event is sent on behalf of.
        """
        return getattr(self, "send_on_behalf_of", None)


def _event_dict_property(key):
    def getter(self):
        return self._event_dict[key]

    def setter(self, v):
        self._event_dict[key] = v

    def delete(self):
        del self._event_dict[key]

    return property(
        getter,
        setter,
        delete,
    )


class EventBase(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, signatures={}, unsigned={},
                 internal_metadata_dict={}, rejected_reason=None):
        self.signatures = signatures
        self.unsigned = unsigned
        self.rejected_reason = rejected_reason

        self.internal_metadata = _EventInternalMetadata(
            internal_metadata_dict
        )

    auth_events = abc.abstractproperty()
    depth = abc.abstractproperty()
    content = abc.abstractproperty()
    hashes = abc.abstractproperty()
    origin = abc.abstractproperty()
    origin_server_ts = abc.abstractproperty()
    prev_events = abc.abstractproperty()
    prev_state = abc.abstractproperty()
    redacts = abc.abstractproperty()
    room_id = abc.abstractproperty()
    sender = abc.abstractproperty()
    user_id = abc.abstractproperty()

    event_id = abc.abstractproperty()
    state_key = abc.abstractproperty()
    type = abc.abstractproperty()

    @abc.abstractmethod
    def get_dict(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def get(self, key, default=None):
        raise NotImplementedError()

    @abc.abstractmethod
    def iteritems(self):
        raise NotImplementedError()

    @property
    def membership(self):
        return self.content["membership"]

    def is_state(self):
        return hasattr(self, "state_key") and self.state_key is not None

    def get_internal_metadata_dict(self):
        return self.internal_metadata.get_dict()

    def get_pdu_json(self, time_now=None):
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


class FrozenEvent(EventBase):
    def __init__(self, event_dict, internal_metadata_dict={}, rejected_reason=None):
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
        self._type = event_dict["type"]
        if "state_key" in event_dict:
            self._state_key = event_dict["state_key"]

        self._event_dict = frozen_dict

        super(FrozenEvent, self).__init__(
            signatures=signatures,
            unsigned=unsigned,
            internal_metadata_dict=internal_metadata_dict,
            rejected_reason=rejected_reason,
        )

    auth_events = _event_dict_property("auth_events")
    depth = _event_dict_property("depth")
    content = _event_dict_property("content")
    hashes = _event_dict_property("hashes")
    origin = _event_dict_property("origin")
    origin_server_ts = _event_dict_property("origin_server_ts")
    prev_events = _event_dict_property("prev_events")
    prev_state = _event_dict_property("prev_state")
    redacts = _event_dict_property("redacts")
    room_id = _event_dict_property("room_id")
    sender = _event_dict_property("sender")
    user_id = _event_dict_property("sender")

    @property
    def event_id(self):
        return self._event_id

    @property
    def type(self):
        return self._type

    @property
    def state_key(self):
        return self._state_key

    def get_dict(self):
        d = dict(self._event_dict)
        d.update({
            "signatures": self.signatures,
            "unsigned": dict(self.unsigned),
        })

        return d

    def get(self, key, default=None):
        return self._event_dict.get(key, default)

    def iteritems(self):
        return self._event_dict.iteritems()

    @staticmethod
    def from_event(event):
        e = FrozenEvent(
            event.get_pdu_json()
        )

        e.internal_metadata = event.internal_metadata

        return e

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<FrozenEvent event_id='%s', type='%s', state_key='%s'>" % (
            self.get("event_id", None),
            self.get("type", None),
            self.get("state_key", None),
        )


def _compact_property(key):
    def getter(self):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(
                "AttributeError: '%s' object has no attribute '%s'" % (
                    self.__name__, key,
                )
            )

    return property(getter)


class _Unsigned(object):
    __slots__ = [
        "age_ts",
        "replaces_state",
        "redacted_because",
        "invite_room_state",
        "prev_content",
        "prev_sender",
        "redacted_by",
    ]

    def __init__(self, **kwargs):
        for s in self.__slots__:
            try:
                setattr(self, s, kwargs[s])
            except KeyError:
                continue

    def __getitem__(self, field):
        try:
            return getattr(self, field)
        except AttributeError:
            raise KeyError(field)

    def __setitem__(self, field, value):
        try:
            setattr(self, field, value)
        except AttributeError:
            raise KeyError(field)

    def __delitem__(self, field):
        try:
            return delattr(self, field)
        except AttributeError:
            raise KeyError(field)

    def __contains__(self, field):
        return hasattr(self, field)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def pop(self, key, default):
        r = self.get(key, default)
        try:
            delattr(self, key)
        except AttributeError:
            pass
        return r

    def __iter__(self):
        for key in self.__slots__:
            if hasattr(self, key):
                yield (key, getattr(self, key))


class CompactEvent(EventBase):
    __slots__ = [
        "event_json",

        "internal_metadata",
        "rejected_reason",

        "signatures",
        "unsigned",

        "event_id",
        "room_id",
        "type",
        "state_key",
        "sender",
    ]

    def __init__(self, event_dict, internal_metadata_dict={}, rejected_reason=None):
        event_dict = dict(unfreeze(event_dict))

        object.__setattr__(self, "unsigned", _Unsigned(**event_dict.pop("unsigned", {})))

        signatures = {
            intern_string(name): {
                intern_string(sig_id): sig.encode("utf-8")
                for sig_id, sig in sigs.iteritems()
            }
            for name, sigs in event_dict.pop("signatures", {}).iteritems()
        }
        object.__setattr__(self, "signatures", signatures)

        object.__setattr__(self, "event_json", json.dumps(event_dict))

        object.__setattr__(self, "rejected_reason", rejected_reason)
        object.__setattr__(self, "internal_metadata", _EventInternalMetadata(
            internal_metadata_dict
        ))

        object.__setattr__(self, "event_id", event_dict["event_id"])
        object.__setattr__(self, "room_id", event_dict["room_id"])
        object.__setattr__(self, "type", event_dict["type"])
        if "state_key" in event_dict:
            object.__setattr__(self, "state_key", event_dict["state_key"])
        object.__setattr__(self, "sender", event_dict["sender"])

    auth_events = _compact_property("auth_events")
    depth = _compact_property("depth")
    content = _compact_property("content")
    hashes = _compact_property("hashes")
    origin = _compact_property("origin")
    origin_server_ts = _compact_property("origin_server_ts")
    prev_events = _compact_property("prev_events")
    prev_state = _compact_property("prev_state")
    redacts = _compact_property("redacts")

    @property
    def user_id(self):
        return self.sender

    @property
    def membership(self):
        return self.content["membership"]

    def is_state(self):
        return hasattr(self, "state_key") and self.state_key is not None

    def get_dict(self):
        d = json.loads(self.event_json)
        d.update({
            "signatures": dict(self.signatures),
            "unsigned": dict(self.unsigned),
        })

        return d

    def get(self, key, default=None):
        if key in self.__slots__:
            return freeze(getattr(self, key, default))

        d = json.loads(self.event_json)
        return d.get(key, default)

    def get_internal_metadata_dict(self):
        return self.internal_metadata.get_dict()

    def __getitem__(self, field):
        if field in self.__slots__:
            try:
                return freeze(getattr(self, field))
            except AttributeError:
                raise KeyError(field)

        d = json.loads(self.event_json)
        return d[field]

    def __contains__(self, field):
        if field in self.__slots__:
            return hasattr(self, field)

        d = json.loads(self.event_json)
        return field in d

    @staticmethod
    def from_event(event):
        return CompactEvent(
            event.get_pdu_json(),
            event.get_internal_metadata_dict(),
            event.rejected_reason,
        )

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<CompactEvent event_id='%s', type='%s', state_key='%s'>" % (
            self.get("event_id", None),
            self.get("type", None),
            self.get("state_key", None),
        )

    def iteritems(self):
        return json.loads(self.event_json).iteritems()

    def __eq__(self, other):
        return self.event_id == other.event_id
