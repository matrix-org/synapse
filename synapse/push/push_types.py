# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from typing import List, Optional

from typing_extensions import TypedDict


class EmailReason(TypedDict, total=False):
    """
    Information on the event that triggered the email to be sent

    Params:
        room_id: the ID of the room the event was sent in
        room_name: a human-readable name for the room the event was sent in
        received_at: the time in milliseconds at which the event was received
        delay_before_mail_ms: the amount of time in milliseconds Synapse always waits
                before ever emailing about a notification (to give the user a chance to respond
                to other push or notice the window)
        last_sent_ts: the time in milliseconds at which a notification was last sent
                for an event in this room
        throttle_ms: the minimum amount of time in milliseconds between two
                notifications can be sent for this room
    """
    room_id: str
    room_name: Optional[str]
    received_at: int
    delay_before_mail_ms: int
    last_sent_ts: int
    throttle_ms: int


class NotifVars(TypedDict):
    link: str
    ts: Optional[int]
    messages: List


class RoomVars(TypedDict):
    title: Optional[str]
    hash: int
    notifs: List
    invite: bool
    link: str
    avatar_url: Optional[str]


class MessageVars(TypedDict, total=False):
    event_type: str
    is_historical: bool
    id: str
    ts: int
    sender_name: str
    sender_avatar_url: Optional[str]
    sender_hash: int
    msgtype: Optional[str]
    body_text_html: str
    body_text_plain: str
    image_url: str
    format: Optional[str]


class TemplateVars(TypedDict, total=False):
    app_name: str
    server_name: str
    link: str
    user_display_name: str
    unsubscribe_link: str
    summary_text: str
    rooms: List
    reason: EmailReason
