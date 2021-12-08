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

    room_id: the ID of the room the event was sent in
    now: timestamp in ms when the email is being sent out
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
    now: int
    room_name: Optional[str]
    received_at: int
    delay_before_mail_ms: int
    last_sent_ts: int
    throttle_ms: int


class MessageVars(TypedDict, total=False):
    """
    Details about a specific message to include in a notification

    event_type: the type of the event
    is_historical: a boolean, which is `False` if the message is the one
                that triggered the notification, `True` otherwise
    id: the ID of the event
    ts: the time in milliseconds at which the event was sent
    sender_name: the display name for the event's sender
    sender_avatar_url: the avatar URL (as a `mxc://` URL) for the event's
                sender
    sender_hash: a hash of the user ID of the sender
    msgtype: the type of the message
    body_text_html: html representation of the message
    body_text_plain: plaintext representation of the message
    image_url: mxc url of an image, when "msgtype" is "m.image"
    """

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


class NotifVars(TypedDict):
    """
    Details about an event we are about to include in a notification

    link: a `matrix.to` link to the event
    ts: the time in milliseconds at which the event was received
    messages: a list of messages containing one message before the event, the
              message in the event, and one message after the event.
    """

    link: str
    ts: Optional[int]
    messages: List[MessageVars]


class RoomVars(TypedDict):
    """
    Represents a room containing events to include in the email.

    title: a human-readable name for the room
    hash: a hash of the ID of the room
    invite: a boolean, which is `True` if the room is an invite the user hasn't
        accepted yet, `False` otherwise
    notifs: a list of events, or an empty list if `invite` is `True`.
    link: a `matrix.to` link to the room
    avator_url: url to the room's avator
    """

    title: Optional[str]
    hash: int
    invite: bool
    notifs: List[NotifVars]
    link: str
    avatar_url: Optional[str]


class TemplateVars(TypedDict, total=False):
    """
    Generic structure for passing to the email sender, can hold all the fields used in email templates.

    app_name: name of the app/service this homeserver is associated with
    server_name: name of our own homeserver
    link: a link to include into the email to be sent
    user_display_name: the display name for the user receiving the notification
    unsubscribe_link: the link users can click to unsubscribe from email notifications
    summary_text: a summary of the notification(s). The text used can be customised
              by configuring the various settings in the `email.subjects` section of the
              configuration file.
    rooms: a list of rooms containing events to include in the email
    reason: information on the event that triggered the email to be sent
    """

    app_name: str
    server_name: str
    link: str
    user_display_name: str
    unsubscribe_link: str
    summary_text: str
    rooms: List[RoomVars]
    reason: EmailReason
