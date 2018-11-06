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

import logging
import os
from distutils.util import strtobool

import six
from six import iteritems

import attr
from canonicaljson import json

logger = logging.getLogger(__name__)

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

    def is_invite_from_remote(self):
        return getattr(self, "invite_from_remote", False)

    def get_send_on_behalf_of(self):
        """Whether this server should send the event on behalf of another server.
        This is used by the federation "send_join" API to forward the initial join
        event for a server in the room.

        returns a str with the name of the server this event is sent on behalf of.
        """
        return getattr(self, "send_on_behalf_of", None)


@attr.s(slots=True, frozen=True, cmp=False, hash=None)
class FrozenEvent(object):
    """A full event, which can't be mutated. Abstracts away differences
    between different event format versions.

    Attributes:
        event_id (str)
        room_id (str)
        sender (str)
        type (str)
        state_key (str): If a state event, the state_key
        depth (int)
        redacts (str|None)
        origin_server_ts (int)
        content (dict)
        signatures (dict)
        hashes (dict)
        unsigned (dict)
        rejected_reason (str|None)
        internal_metadata (_EventInternalMetadata)
    """

    event_id = attr.ib()
    room_id = attr.ib()
    sender = attr.ib()
    type = attr.ib()
    _state_key = attr.ib()
    depth = attr.ib()
    redacts = attr.ib()
    origin_server_ts = attr.ib()
    content = attr.ib()
    signatures = attr.ib()
    hashes = attr.ib()
    unsigned = attr.ib()
    rejected_reason = attr.ib()
    internal_metadata = attr.ib()

    _auth_event_ids = attr.ib()  # tuple[str]: list of auth event IDs
    _prev_event_ids = attr.ib()  # tuple[str]: list of prev event IDs
    # str: the serialized event json, minus "unsigned" and "signatures" keys
    _json = attr.ib()

    @staticmethod
    def from_v1(event_dict, internal_metadata_dict={}, rejected_reason=None,
                event_json=None):
        """Creates a FrozenEvent from a v1 event

        Args:
            event_dict (dict)
            internal_metadata_dict (dict)
            rejected_reason (str|None): If set the event was rejected for the
                given reason.
            event_json (str|None): If set the json string `event_dict` was
                parse from. If not given then it will be calculated by
                serializing `event_dict`

        Returns:
            FrozenEvent
        """
        event_dict = dict(event_dict)  # We copy this as we're going to remove stuff

        # A lot of this is optional because the tests don't actually define them
        event_id = event_dict.get("event_id")
        room_id = event_dict.get("room_id")
        sender = event_dict.get("sender")
        event_type = event_dict.get("type")
        _state_key = event_dict.get("state_key")
        depth = event_dict.get("depth")
        redacts = event_dict.get("redacts")
        origin_server_ts = event_dict.get("origin_server_ts")

        # TODO: We should replace this with something that can't be modified
        content = dict(event_dict.get("content", {}))

        # Some events apparently don't have a 'hashes' field
        # TODO: Can we compress this? Freeze it somehow?
        hashes = event_dict.get("hashes", {})

        _auth_event_ids = tuple(e for e, _ in event_dict.get("auth_events", []))
        _prev_event_ids = tuple(e for e, _ in event_dict.get("prev_events", []))

        # Signatures is a dict of dicts, and this is faster than doing a
        # copy.deepcopy
        # TODO: Can we compress this? We could convert the base64 to bytes?
        signatures = {
            name: {
                sig_id: sig
                for sig_id, sig in iteritems(sigs)
            }
            for name, sigs in iteritems(event_dict.pop("signatures", {}))
        }

        unsigned = dict(event_dict.pop("unsigned", {}))

        if not event_json:
            event_json = json.dumps(event_dict)

        rejected_reason = rejected_reason
        internal_metadata = _EventInternalMetadata(
            internal_metadata_dict
        )

        return FrozenEvent(
            event_id=event_id,
            room_id=room_id,
            sender=sender,
            type=event_type,
            state_key=_state_key,
            depth=depth,
            redacts=redacts,
            origin_server_ts=origin_server_ts,
            content=content,
            signatures=signatures,
            hashes=hashes,
            auth_event_ids=_auth_event_ids,
            prev_event_ids=_prev_event_ids,
            unsigned=unsigned,
            json=event_json,
            rejected_reason=rejected_reason,
            internal_metadata=internal_metadata,
        )

    def copy(self):
        return FrozenEvent(
            event_id=self.event_id,
            room_id=self.room_id,
            sender=self.sender,
            type=self.type,
            state_key=self._state_key,
            depth=self.depth,
            redacts=self.redacts,
            origin_server_ts=self.origin_server_ts,
            content=dict(self.content),
            signatures=dict(self.signatures),
            hashes=dict(self.hashes),
            auth_event_ids=self._auth_event_ids,
            prev_event_ids=self._prev_event_ids,
            unsigned=dict(self.unsigned),
            json=self._json,
            rejected_reason=self.rejected_reason,
            internal_metadata=_EventInternalMetadata(
                self.internal_metadata.get_dict(),
            ),
        )

    @property
    def state_key(self):
        if self._state_key is not None:
            return self._state_key
        raise AttributeError("state_key")

    @property
    def membership(self):
        return self.content["membership"]

    def auth_event_ids(self):
        return self._auth_event_ids

    def prev_event_ids(self):
        return self._prev_event_ids

    def is_state(self):
        return hasattr(self, "state_key") and self.state_key is not None

    def get_dict(self):
        pdu_json = json.loads(self._json)
        pdu_json["unsigned"] = self.unsigned
        pdu_json["signatures"] = self.signatures
        return pdu_json

    def get_pdu_json(self, time_now=None):
        pdu_json = self.get_dict()

        unsigned = dict(pdu_json["unsigned"])
        if time_now is not None and "age_ts" in unsigned:
            age = time_now - unsigned["age_ts"]
            unsigned["age"] = int(age)
            del unsigned["age_ts"]

        # This may be a frozen event
        unsigned.pop("redacted_because", None)

        pdu_json["unsigned"] = unsigned

        return pdu_json

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<FrozenEvent event_id='%s', type='%s', state_key='%s'>" % (
            self.event_id,
            self.type,
            self._state_key,
        )

    # FIXME: We probably want to get rid of the below functions

    def get(self, key, default=None):
        keys = ("sender", "hashes", "state_key", "room_id", "type", "content")
        if key in keys:
            return getattr(self, key, default)

        raise NotImplementedError(key)

    def items(self):
        return list(self.get_dict().items())

    def keys(self):
        return six.iterkeys(self.get_dict())

    @property
    def user_id(self):
        return self.sender

    @property
    def prev_state(self):
        return []
