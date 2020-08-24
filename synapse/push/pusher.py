# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

import logging

from synapse.push.emailpusher import EmailPusher
from synapse.push.mailer import Mailer

from .httppusher import HttpPusher

logger = logging.getLogger(__name__)


class PusherFactory(object):
    def __init__(self, hs):
        self.hs = hs
        self.config = hs.config

        self.pusher_types = {"http": HttpPusher}

        logger.info("email enable notifs: %r", hs.config.email_enable_notifs)
        if hs.config.email_enable_notifs:
            self.mailers = {}  # app_name -> Mailer

            self._notif_template_html = hs.config.email_notif_template_html
            self._notif_template_text = hs.config.email_notif_template_text

            self.pusher_types["email"] = self._create_email_pusher

            logger.info("defined email pusher type")

    def create_pusher(self, pusherdict):
        kind = pusherdict["kind"]
        f = self.pusher_types.get(kind, None)
        if not f:
            return None
        logger.debug("creating %s pusher for %r", kind, pusherdict)
        return f(self.hs, pusherdict)

    def _create_email_pusher(self, _hs, pusherdict):
        app_name = self._app_name_from_pusherdict(pusherdict)
        mailer = self.mailers.get(app_name)
        if not mailer:
            mailer = Mailer(
                hs=self.hs,
                app_name=app_name,
                template_html=self._notif_template_html,
                template_text=self._notif_template_text,
            )
            self.mailers[app_name] = mailer
        return EmailPusher(self.hs, pusherdict, mailer)

    def _app_name_from_pusherdict(self, pusherdict):
        data = pusherdict["data"]

        if isinstance(data, dict):
            brand = data.get("brand")
            if isinstance(brand, str):
                return brand

        return self.config.email_app_name
