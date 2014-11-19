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

from synapse.util.jsonobject import JsonEncodedObject


def serialize_event(hs, e):
    # FIXME(erikj): To handle the case of presence events and the like
    if not isinstance(e, SynapseEvent):
        return e

    # Should this strip out None's?
    d = {k: v for k, v in e.get_dict().items()}
    if "age_ts" in d:
        d["age"] = int(hs.get_clock().time_msec()) - d["age_ts"]
        del d["age_ts"]

    return d


class SynapseEvent(JsonEncodedObject):

    """Base class for Synapse events. These are JSON objects which must abide
    by a certain well-defined structure.
    """

    # Attributes that are currently assumed by the federation side:
    # Mandatory:
    # - event_id
    # - room_id
    # - type
    # - is_state
    #
    # Optional:
    # - state_key (mandatory when is_state is True)
    # - prev_events (these can be filled out by the federation layer itself.)
    # - prev_state

    valid_keys = [
        "event_id",
        "type",
        "room_id",
        "user_id",  # sender/initiator
        "content",  # HTTP body, JSON
        "state_key",
        "age_ts",
        "prev_content",
        "replaces_state",
        "redacted_because",
        "origin_server_ts",
    ]

    internal_keys = [
        "is_state",
        "depth",
        "destinations",
        "origin",
        "outlier",
        "redacted",
        "prev_events",
        "hashes",
        "signatures",
        "prev_state",
        "auth_events",
        "state_hash",
    ]

    required_keys = [
        "event_id",
        "room_id",
        "content",
    ]

    def __init__(self, raises=True, **kwargs):
        super(SynapseEvent, self).__init__(**kwargs)
        # if "content" in kwargs:
        #     self.check_json(self.content, raises=raises)

    def get_content_template(self):
        """ Retrieve the JSON template for this event as a dict.

        The template must be a dict representing the JSON to match. Only
        required keys should be present. The values of the keys in the template
        are checked via type() to the values of the same keys in the actual
        event JSON.

        NB: If loading content via json.loads, you MUST define strings as
        unicode.

        For example:
            Content:
                {
                    "name": u"bob",
                    "age": 18,
                    "friends": [u"mike", u"jill"]
                }
            Template:
                {
                    "name": u"string",
                    "age": 0,
                    "friends": [u"string"]
                }
            The values "string" and 0 could be anything, so long as the types
            are the same as the content.
        """
        raise NotImplementedError("get_content_template not implemented.")

    def get_pdu_json(self, time_now=None):
        pdu_json = self.get_full_dict()
        pdu_json.pop("destinations", None)
        pdu_json.pop("outlier", None)
        pdu_json.pop("replaces_state", None)
        pdu_json.pop("redacted", None)
        state_hash = pdu_json.pop("state_hash", None)
        if state_hash is not None:
            pdu_json.setdefault("unsigned", {})["state_hash"] = state_hash
        content = pdu_json.get("content", {})
        content.pop("prev", None)
        if time_now is not None and "age_ts" in pdu_json:
            age = time_now - pdu_json["age_ts"]
            pdu_json.setdefault("unsigned", {})["age"] = int(age)
            del pdu_json["age_ts"]
        user_id = pdu_json.pop("user_id")
        pdu_json["sender"] = user_id
        return pdu_json


class SynapseStateEvent(SynapseEvent):

    def __init__(self, **kwargs):
        if "state_key" not in kwargs:
            kwargs["state_key"] = ""
        super(SynapseStateEvent, self).__init__(**kwargs)
