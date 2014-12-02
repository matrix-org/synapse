# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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


class _EventInternalMetadata(object):
    def __init__(self, internal_metadata_dict):
        self.__dict__ = internal_metadata_dict

    def get_dict(self):
        return dict(self.__dict__)


class Event(object):
    def __init__(self, event_dict, internal_metadata_dict={}):
        self._signatures = event_dict.get("signatures", {})
        self._unsigned = event_dict.get("unsigned", {})

        self._original = {
            k: v
            for k, v in event_dict.items()
            if k not in ["signatures", "unsigned"]
        }

        self._event_dict = frozendict(self._original)

        self.internal_metadata = _EventInternalMetadata(
            internal_metadata_dict
        )

    @property
    def auth_events(self):
        return self._event_dict["auth_events"]

    @property
    def content(self):
        return self._event_dict["content"]

    @property
    def event_id(self):
        return self._event_dict["event_id"]

    @property
    def hashes(self):
        return self._event_dict["hashes"]

    @property
    def origin(self):
        return self._event_dict["origin"]

    @property
    def prev_events(self):
        return self._event_dict["prev_events"]

    @property
    def prev_state(self):
        return self._event_dict["prev_state"]

    @property
    def room_id(self):
        return self._event_dict["room_id"]

    @property
    def signatures(self):
        return self._signatures

    @property
    def state_key(self):
        return self._event_dict["state_key"]

    @property
    def type(self):
        return self._event_dict["type"]

    @property
    def unsigned(self):
        return self._unsigned

    @property
    def user_id(self):
        return self._event_dict["sender"]

    @property
    def sender(self):
        return self._event_dict["sender"]

    def get_dict(self):
        d = dict(self._original)
        d.update({
            "signatures": self._signatures,
            "unsigned": self._unsigned,
        })

        return d

    def get_internal_metadata_dict(self):
        return self.internal_metadata.get_dict()

    def get_pdu_json(self, time_now=None):
        pdu_json = self.get_dict()

        if time_now is not None and "age_ts" in pdu_json["unsigned"]:
            age = time_now - pdu_json["unsigned"]["age_ts"]
            pdu_json.setdefault("unsigned", {})["age"] = int(age)
            del pdu_json["unsigned"]["age_ts"]

        return pdu_json