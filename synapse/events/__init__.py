# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
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

import os
from distutils.util import strtobool

import six

from unpaddedbase64 import encode_base64

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, EventFormatVersions
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


class _EventInternalMetadata(object):
    def __init__(self, internal_metadata_dict):
        self.__dict__ = dict(internal_metadata_dict)

    def get_dict(self):
        return dict(self.__dict__)

    def is_outlier(self):
        return getattr(self, "outlier", False)

    def is_out_of_band_membership(self):
        """Whether this is an out of band membership, like an invite or an invite
        rejection. This is needed as those events are marked as outliers, but
        they still need to be processed as if they're new events (e.g. updating
        invite state in the database, relaying to clients, etc).
        """
        return getattr(self, "out_of_band_membership", False)

    def get_send_on_behalf_of(self):
        """Whether this server should send the event on behalf of another server.
        This is used by the federation "send_join" API to forward the initial join
        event for a server in the room.

        returns a str with the name of the server this event is sent on behalf of.
        """
        return getattr(self, "send_on_behalf_of", None)

    def need_to_check_redaction(self):
        """Whether the redaction event needs to be rechecked when fetching
        from the database.

        Starting in room v3 redaction events are accepted up front, and later
        checked to see if the redacter and redactee's domains match.

        If the sender of the redaction event is allowed to redact any event
        due to auth rules, then this will always return false.

        Returns:
            bool
        """
        return getattr(self, "recheck_redaction", False)

    def is_soft_failed(self):
        """Whether the event has been soft failed.

        Soft failed events should be handled as usual, except:
            1. They should not go down sync or event streams, or generally
               sent to clients.
            2. They should not be added to the forward extremities (and
               therefore not to current state).

        Returns:
            bool
        """
        return getattr(self, "soft_failed", False)


def _event_dict_property(key):
    # We want to be able to use hasattr with the event dict properties.
    # However, (on python3) hasattr expects AttributeError to be raised. Hence,
    # we need to transform the KeyError into an AttributeError
    def getter(self):
        try:
            return self._event_dict[key]
        except KeyError:
            raise AttributeError(key)

    def setter(self, v):
        try:
            self._event_dict[key] = v
        except KeyError:
            raise AttributeError(key)

    def delete(self):
        try:
            del self._event_dict[key]
        except KeyError:
            raise AttributeError(key)

    return property(
        getter,
        setter,
        delete,
    )


class EventBase(object):
    def __init__(self, event_dict, signatures={}, unsigned={},
                 internal_metadata_dict={}, rejected_reason=None):
        self.signatures = signatures
        self.unsigned = unsigned
        self.rejected_reason = rejected_reason

        self._event_dict = event_dict

        self.internal_metadata = _EventInternalMetadata(
            internal_metadata_dict
        )

    auth_events = _event_dict_property("auth_events")
    depth = _event_dict_property("depth")
    content = _event_dict_property("content")
    hashes = _event_dict_property("hashes")
    origin = _event_dict_property("origin")
    origin_server_ts = _event_dict_property("origin_server_ts")
    prev_events = _event_dict_property("prev_events")
    redacts = _event_dict_property("redacts")
    room_id = _event_dict_property("room_id")
    sender = _event_dict_property("sender")
    user_id = _event_dict_property("sender")

    @property
    def membership(self):
        return self.content["membership"]

    def is_state(self):
        return hasattr(self, "state_key") and self.state_key is not None

    def get_dict(self):
        d = dict(self._event_dict)
        d.update({
            "signatures": self.signatures,
            "unsigned": dict(self.unsigned),
        })

        return d

    def get(self, key, default=None):
        return self._event_dict.get(key, default)

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

    def __getitem__(self, field):
        return self._event_dict[field]

    def __contains__(self, field):
        return field in self._event_dict

    def items(self):
        return list(self._event_dict.items())

    def keys(self):
        return six.iterkeys(self._event_dict)

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

        self.event_id = event_dict["event_id"]
        self.type = event_dict["type"]
        if "state_key" in event_dict:
            self.state_key = event_dict["state_key"]

        super(FrozenEvent, self).__init__(
            frozen_dict,
            signatures=signatures,
            unsigned=unsigned,
            internal_metadata_dict=internal_metadata_dict,
            rejected_reason=rejected_reason,
        )

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

    def __init__(self, event_dict, internal_metadata_dict={}, rejected_reason=None):
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
        self.type = event_dict["type"]
        if "state_key" in event_dict:
            self.state_key = event_dict["state_key"]

        super(FrozenEventV2, self).__init__(
            frozen_dict,
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
        return "<FrozenEventV2 event_id='%s', type='%s', state_key='%s'>" % (
            self.event_id,
            self.get("type", None),
            self.get("state_key", None),
        )


def room_version_to_event_format(room_version):
    """Converts a room version string to the event format

    Args:
        room_version (str)

    Returns:
        int
    """
    v = KNOWN_ROOM_VERSIONS.get(room_version)

    if not v:
        # We should have already checked version, so this should not happen
        raise RuntimeError("Unrecognized room version %s" % (room_version,))

    return v.event_format


def event_type_from_format_version(format_version):
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
    else:
        raise Exception(
            "No event format %r" % (format_version,)
        )
