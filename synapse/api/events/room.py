# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from synapse.api.constants import Feedback, Membership
from synapse.api.errors import SynapseError
from . import SynapseEvent, SynapseStateEvent


class GenericEvent(SynapseEvent):
    def get_content_template(self):
        return {}


class RoomTopicEvent(SynapseEvent):
    TYPE = "m.room.topic"

    internal_keys = SynapseEvent.internal_keys + [
        "topic",
    ]

    def __init__(self, **kwargs):
        kwargs["state_key"] = ""
        if "topic" in kwargs["content"]:
            kwargs["topic"] = kwargs["content"]["topic"]
        super(RoomTopicEvent, self).__init__(**kwargs)

    def get_content_template(self):
        return {"topic": u"string"}


class RoomNameEvent(SynapseEvent):
    TYPE = "m.room.name"

    internal_keys = SynapseEvent.internal_keys + [
        "name",
    ]

    def __init__(self, **kwargs):
        kwargs["state_key"] = ""
        if "name" in kwargs["content"]:
            kwargs["name"] = kwargs["content"]["name"]
        super(RoomNameEvent, self).__init__(**kwargs)

    def get_content_template(self):
        return {"name": u"string"}


class RoomMemberEvent(SynapseEvent):
    TYPE = "m.room.member"

    valid_keys = SynapseEvent.valid_keys + [
        # target is the state_key
        "membership",  # action
    ]

    def __init__(self, **kwargs):
        if "membership" not in kwargs:
            kwargs["membership"] = kwargs.get("content", {}).get("membership")
        if not kwargs["membership"] in Membership.LIST:
            raise SynapseError(400, "Bad membership value.")
        super(RoomMemberEvent, self).__init__(**kwargs)

    def get_content_template(self):
        return {"membership": u"string"}


class MessageEvent(SynapseEvent):
    TYPE = "m.room.message"

    valid_keys = SynapseEvent.valid_keys + [
        "msg_id",  # unique per room + user combo
    ]

    def __init__(self, **kwargs):
        super(MessageEvent, self).__init__(**kwargs)

    def get_content_template(self):
        return {"msgtype": u"string"}


class FeedbackEvent(SynapseEvent):
    TYPE = "m.room.message.feedback"

    valid_keys = SynapseEvent.valid_keys

    def __init__(self, **kwargs):
        super(FeedbackEvent, self).__init__(**kwargs)
        if not kwargs["content"]["type"] in Feedback.LIST:
            raise SynapseError(400, "Bad feedback value.")

    def get_content_template(self):
        return {
            "type": u"string",
            "target_event_id": u"string",
            "msg_sender_id": u"string"
        }


class InviteJoinEvent(SynapseEvent):
    TYPE = "m.room.invite_join"

    valid_keys = SynapseEvent.valid_keys + [
        # target_user_id is the state_key
        "target_host",
    ]

    def __init__(self, **kwargs):
        super(InviteJoinEvent, self).__init__(**kwargs)

    def get_content_template(self):
        return {}


class RoomConfigEvent(SynapseEvent):
    TYPE = "m.room.config"

    def __init__(self, **kwargs):
        kwargs["state_key"] = ""
        super(RoomConfigEvent, self).__init__(**kwargs)

    def get_content_template(self):
        return {}


class RoomCreateEvent(SynapseStateEvent):
    TYPE = "m.room.create"

    def get_content_template(self):
        return {}


class RoomJoinRulesEvent(SynapseStateEvent):
    TYPE = "m.room.join_rules"

    def get_content_template(self):
        return {}


class RoomPowerLevelsEvent(SynapseStateEvent):
    TYPE = "m.room.power_levels"

    def get_content_template(self):
        return {}


class RoomDefaultLevelEvent(SynapseStateEvent):
    TYPE = "m.room.default_level"

    def get_content_template(self):
        return {}
