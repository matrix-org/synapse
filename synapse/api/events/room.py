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
from . import SynapseEvent


class RoomTopicEvent(SynapseEvent):
    TYPE = "m.room.topic"

    def __init__(self, **kwargs):
        kwargs["state_key"] = ""
        super(RoomTopicEvent, self).__init__(**kwargs)

    def get_content_template(self):
        return {"topic": u"string"}


class RoomMemberEvent(SynapseEvent):
    TYPE = "m.room.member"

    valid_keys = SynapseEvent.valid_keys + [
        "target_user_id",  # target
        "membership",  # action
    ]

    def __init__(self, **kwargs):
        if "target_user_id" in kwargs:
            kwargs["state_key"] = kwargs["target_user_id"]
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

    valid_keys = SynapseEvent.valid_keys + [
        "msg_id",  # the message ID being acknowledged
        "msg_sender_id",  # person who is sending the feedback is 'user_id'
        "feedback_type",  # the type of feedback (delivery, read, etc)
    ]

    def __init__(self, **kwargs):
        super(FeedbackEvent, self).__init__(**kwargs)

    def get_content_template(self):
        return {}


class InviteJoinEvent(SynapseEvent):
    TYPE = "m.room.invite_join"

    valid_keys = SynapseEvent.valid_keys + [
        "target_user_id",
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
