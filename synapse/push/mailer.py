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

import jinja2


class Mailer(object):
    def __init__(self, hs):
        self.hs = hs
        loader = jinja2.FileSystemLoader(self.hs.config.email_template_dir)
        env = jinja2.Environment(loader=loader)
        self.notif_template = env.get_template(self.hs.config.email_notif_template_html)

    @defer.inlineCallbacks
    def send_notification_mail(self, user_id, email_address, push_actions):
        raw_from = email.utils.parseaddr(self.hs.config.email_notif_from)[1]
        raw_to = email.utils.parseaddr(email_address)[1]

        if raw_to == '':
            raise RuntimeError("Invalid 'to' address")

        plainText = self.notif_template.render()

        text_part = MIMEText(plainText, "plain")
        text_part['Subject'] = "New Matrix Notifications"
        text_part['From'] = self.hs.config.email_notif_from
        text_part['To'] = email_address

        yield sendmail(
            self.hs.config.email_smtp_host,
            raw_from, raw_to, text_part.as_string(),
            port=self.hs.config.email_smtp_port
        )
