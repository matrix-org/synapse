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
from synapse.util.presentable_names import (
    calculate_room_name, name_from_member_event, descriptor_from_member_events
)
from synapse.types import UserID
from synapse.api.errors import StoreError

import jinja2
import bleach

import time
import urllib


MESSAGE_FROM_PERSON_IN_ROOM = "You have a message from %s in the %s room"
MESSAGE_FROM_PERSON = "You have a message from %s"
MESSAGES_FROM_PERSON = "You have messages from %s"
MESSAGES_IN_ROOM = "There are some messages for you in the %s room"
MESSAGES_IN_ROOMS = "Here are some messages you may have missed"

CONTEXT_BEFORE = 1

# From https://github.com/matrix-org/matrix-react-sdk/blob/master/src/HtmlUtils.js
ALLOWED_TAGS = [
    'font',  # custom to matrix for IRC-style font coloring
    'del',  # for markdown
    # deliberately no h1/h2 to stop people shouting.
    'h3', 'h4', 'h5', 'h6', 'blockquote', 'p', 'a', 'ul', 'ol',
    'nl', 'li', 'b', 'i', 'u', 'strong', 'em', 'strike', 'code', 'hr', 'br', 'div',
    'table', 'thead', 'caption', 'tbody', 'tr', 'th', 'td', 'pre'
]
ALLOWED_ATTRS = {
    # custom ones first:
    "font": ["color"],  # custom to matrix
    "a": ["href", "name", "target"],  # remote target: custom to matrix
    # We don't currently allow img itself by default, but this
    # would make sense if we did
    "img": ["src"],
}
ALLOWED_SCHEMES = ["http", "https", "ftp", "mailto"]


class Mailer(object):
    def __init__(self, hs):
        self.hs = hs
        self.store = self.hs.get_datastore()
        self.state_handler = self.hs.get_state_handler()
        loader = jinja2.FileSystemLoader(self.hs.config.email_template_dir)
        env = jinja2.Environment(loader=loader)
        env.filters["format_ts"] = format_ts_filter
        env.filters["mxc_to_http"] = self.mxc_to_http_filter
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

        notif_events = yield self.store.get_events(
            [pa['event_id'] for pa in push_actions]
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

        rooms = []

        for r in rooms_in_order:
            vars = yield self.get_room_vars(
                r, user_id, notifs_by_room[r], notif_events, state_by_room[r]
            )
            rooms.append(vars)

        summary_text = self.make_summary_text(
            notifs_by_room, state_by_room, notif_events, user_id
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

    @defer.inlineCallbacks
    def get_room_vars(self, room_id, user_id, notifs, notif_events, room_state):
        room_vars = {
            "title": calculate_room_name(room_state, user_id),
            "hash": string_ordinal_total(room_id),  # See sender avatar hash
            "notifs": [],
        }

        for n in notifs:
            vars = yield self.get_notif_vars(n, notif_events[n['event_id']], room_state)
            room_vars['notifs'].append(vars)

        defer.returnValue(room_vars)

    @defer.inlineCallbacks
    def get_notif_vars(self, notif, notif_event, room_state):
        results = yield self.store.get_events_around(
            notif['room_id'], notif['event_id'],
            before_limit=CONTEXT_BEFORE, after_limit=0
        )

        ret = {
            "link": self.make_notif_link(notif),
            "ts": notif['received_ts'],
            "messages": [],
        }

        for event in results['events_before']:
            vars = self.get_message_vars(notif, event, room_state)
            if vars is not None:
                ret['messages'].append(vars)

        vars = self.get_message_vars(notif, notif_event, room_state)
        if vars is not None:
            ret['messages'].append(vars)

        defer.returnValue(ret)

    def get_message_vars(self, notif, event, room_state):
        msgtype = event.content["msgtype"]

        sender_state_event = room_state[("m.room.member", event.sender)]
        sender_name = name_from_member_event(sender_state_event)
        sender_avatar_url = sender_state_event.content["avatar_url"]

        # 'hash' for deterministically picking default images: use
        # sender_hash % the number of default images to choose from
        sender_hash = string_ordinal_total(event.sender)

        ret = {
            "msgtype": msgtype,
            "is_historical": event.event_id != notif['event_id'],
            "ts": event.origin_server_ts,
            "sender_name": sender_name,
            "sender_avatar_url": sender_avatar_url,
            "sender_hash": sender_hash,
        }

        if msgtype == "m.text":
            ret["body_text_plain"] = event.content["body"]
        elif msgtype == "org.matrix.custom.html":
            ret["body_text_html"] = safe_markup(event.content["formatted_body"])

        return ret

    def make_summary_text(self, notifs_by_room, state_by_room, notif_events, user_id):
        if len(notifs_by_room) == 1:
            # Only one room has new stuff
            room_id = notifs_by_room.keys()[0]

            # If the room has some kind of name, use it, but we don't
            # want the generated-from-names one here otherwise we'll
            # end up with, "new message from Bob in the Bob room"
            room_name = calculate_room_name(
                state_by_room[room_id], user_id, fallback_to_members=False
            )

            sender_name = None
            if len(notifs_by_room[room_id]) == 1:
                # There is just the one notification, so give some detail
                event = notif_events[notifs_by_room[room_id][0]["event_id"]]
                if ("m.room.member", event.sender) in state_by_room[room_id]:
                    state_event = state_by_room[room_id][("m.room.member", event.sender)]
                    sender_name = name_from_member_event(state_event)
                if sender_name is not None and room_name is not None:
                    return MESSAGE_FROM_PERSON_IN_ROOM % (sender_name, room_name)
                elif sender_name is not None:
                    return MESSAGE_FROM_PERSON % (sender_name,)
            else:
                # There's more than one notification for this room, so just
                # say there are several
                if room_name is not None:
                    return MESSAGES_IN_ROOM % (room_name,)
                else:
                    # If the room doesn't have a name, say who the messages
                    # are from explicitly to avoid, "messages in the Bob room"
                    sender_ids = list(set([
                        notif_events[n['event_id']].sender
                        for n in notifs_by_room[room_id]
                    ]))

                    return MESSAGES_FROM_PERSON % (
                        descriptor_from_member_events([
                            state_by_room[room_id][("m.room.member", s)] for s in sender_ids
                        ])
                    )
        else:
            # Stuff's happened in multiple different rooms
            return MESSAGES_IN_ROOMS

    def make_notif_link(self, notif):
        return "https://matrix.to/%s/%s" % (
            notif['room_id'], notif['event_id']
        )

    def make_unsubscribe_link(self):
        return "https://vector.im/#/settings"  # XXX: matrix.to

    def mxc_to_http_filter(self, value, width, height, resizeMethod="crop"):
        if value[0:6] != "mxc://":
            return ""
        serverAndMediaId = value[6:]
        params = {
            "width": width,
            "height": height,
            "method": resizeMethod,
        }
        return "%s_matrix/media/v1/thumbnail/%s?%s" % (
            self.hs.config.public_baseurl,
            serverAndMediaId,
            urllib.urlencode(params)
        )


def safe_markup(self, raw_html):
    return jinja2.Markup(bleach.linkify(bleach.clean(
        raw_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS,
        protocols=ALLOWED_SCHEMES, strip=True
    )))


def deduped_ordered_list(l):
    seen = set()
    ret = []
    for item in l:
        if item not in seen:
            seen.add(item)
            ret.append(item)
    return ret

def string_ordinal_total(s):
    tot = 0
    for c in s:
        tot += ord(c)
    return tot

def format_ts_filter(value, format):
    return time.strftime(format, time.localtime(value / 1000))
