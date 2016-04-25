# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

from twisted.internet import defer
from twisted.mail.smtp import sendmail

import email.utils
import email.mime.multipart
from email.mime.text import MIMEText

from synapse.util.async import concurrently_execute
from synapse.util.presentable_names import calculate_room_name, name_from_member_event
from synapse.types import UserID
from synapse.api.errors import StoreError

import jinja2


MESSAGE_FROM_PERSON_IN_ROOM = "You have a message from %s in the %s room"
MESSAGE_FROM_PERSON = "You have a message from %s"
MESSAGES_IN_ROOM = "There are some messages for you in the %s room"
MESSAGES_IN_ROOMS = "Here are some messages you may have missed"


class Mailer(object):
    def __init__(self, hs):
        self.hs = hs
        self.store = self.hs.get_datastore()
        self.state_handler = self.hs.get_state_handler()
        loader = jinja2.FileSystemLoader(self.hs.config.email_template_dir)
        env = jinja2.Environment(loader=loader)
        self.notif_template = env.get_template(self.hs.config.email_notif_template_html)

    @defer.inlineCallbacks
    def send_notification_mail(self, user_id, email_address, push_actions):
        raw_from = email.utils.parseaddr(self.hs.config.email_notif_from)[1]
        raw_to = email.utils.parseaddr(email_address)[1]

        if raw_to == '':
            raise RuntimeError("Invalid 'to' address")

        rooms_in_order = deduped_ordered_list(
            [pa['room_id'] for pa in push_actions]
        )

        notifs_by_room = {}
        for pa in push_actions:
            notifs_by_room.setdefault(pa["room_id"], []).append(pa)

        # collect the current state for all the rooms in which we have
        # notifications
        state_by_room = {}

        try:
            user_display_name = yield self.store.get_profile_displayname(
                UserID.from_string(user_id).localpart
            )
        except StoreError:
            user_display_name = user_id

        @defer.inlineCallbacks
        def _fetch_room_state(room_id):
            room_state = yield self.state_handler.get_current_state(room_id)
            state_by_room[room_id] = room_state

        # Run at most 3 of these at once: sync does 10 at a time but email
        # notifs are much realtime than sync so we can afford to wait a bit.
        yield concurrently_execute(_fetch_room_state, rooms_in_order, 3)

        rooms = [
            self.get_room_vars(
                r, user_id, notifs_by_room[r], state_by_room[r]
            ) for r in rooms_in_order
        ]

        summary_text = yield self.make_summary_text(
            notifs_by_room, state_by_room, user_id
        )

        template_vars = {
            "user_display_name": user_display_name,
            "unsubscribe_link": self.make_unsubscribe_link(),
            "summary_text": summary_text,
            "rooms": rooms,
        }

        plainText = self.notif_template.render(**template_vars)

        text_part = MIMEText(plainText, "html", "utf8")
        text_part['Subject'] = "New Matrix Notifications"
        text_part['From'] = self.hs.config.email_notif_from
        text_part['To'] = email_address

        yield sendmail(
            self.hs.config.email_smtp_host,
            raw_from, raw_to, text_part.as_string(),
            port=self.hs.config.email_smtp_port
        )

    def get_room_vars(self, room_id, user_id, notifs, room_state):
        room_vars = {}
        room_vars['title'] = calculate_room_name(room_state, user_id)
        return room_vars

    @defer.inlineCallbacks
    def make_summary_text(self, notifs_by_room, state_by_room, user_id):
        if len(notifs_by_room) == 1:
            room_id = notifs_by_room.keys()[0]
            sender_name = None
            if len(notifs_by_room[room_id]) == 1:
                # If the room has some kind of name, use it, but we don't
                # want the generated-from-names one here otherwise we'll
                # end up with, "new message from Bob in the Bob room"
                room_name = calculate_room_name(
                    state_by_room[room_id], user_id, fallback_to_members=False
                )
                event = yield self.store.get_event(
                    notifs_by_room[room_id][0]["event_id"]
                )
                if ("m.room.member", event.sender) in state_by_room[room_id]:
                    state_event = state_by_room[room_id][("m.room.member", event.sender)]
                    sender_name = name_from_member_event(state_event)
                if sender_name is not None and room_name is not None:
                    defer.returnValue(
                        MESSAGE_FROM_PERSON_IN_ROOM % (sender_name, room_name)
                    )
                elif sender_name is not None:
                    defer.returnValue(MESSAGE_FROM_PERSON % (sender_name,))
            else:
                room_name = calculate_room_name(state_by_room[room_id], user_id)
                defer.returnValue(MESSAGES_IN_ROOM % (room_name,))
        else:
            defer.returnValue(MESSAGES_IN_ROOMS)

        defer.returnValue("Some thing have occurred in some rooms")

    def make_unsubscribe_link(self):
        return "https://vector.im/#/settings"  # XXX: matrix.to


def deduped_ordered_list(l):
    seen = set()
    ret = []
    for item in l:
        if item not in seen:
            seen.add(item)
            ret.append(item)
    return ret
