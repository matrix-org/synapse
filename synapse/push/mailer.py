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
from synapse.util.room_name import calculate_room_name

import jinja2


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

        template_vars = {
            "unsubscribe_link": self.make_unsubscribe_link(),
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