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

from .httppusher import HttpPusher

logger = logging.getLogger(__name__)

# We try importing this if we can (it will fail if we don't
# have the optional email dependencies installed). We don't
# yet have the config to know if we need the email pusher,
# but importing this after daemonizing seems to fail
# (even though a simple test of importing from a daemonized
# process works fine)
try:
    from synapse.push.emailpusher import EmailPusher
    from synapse.push.mailer import Mailer, load_jinja2_templates
except Exception:
    pass


class PusherFactory(object):
    def __init__(self, hs):
        self.hs = hs

        self.pusher_types = {"http": HttpPusher}

        logger.info("email enable notifs: %r", hs.config.email_enable_notifs)
        if hs.config.email_enable_notifs:
            self.mailers = {}  # app_name -> Mailer

            templates = load_jinja2_templates(
                config=hs.config,
                template_html_name=hs.config.email_notif_template_html,
                template_text_name=hs.config.email_notif_template_text,
            )
            self.notif_template_html, self.notif_template_text = templates

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
                template_html=self.notif_template_html,
                template_text=self.notif_template_text,
            )
            self.mailers[app_name] = mailer
        return EmailPusher(self.hs, pusherdict, mailer)

    def _app_name_from_pusherdict(self, pusherdict):
        if "data" in pusherdict and "brand" in pusherdict["data"]:
            app_name = pusherdict["data"]["brand"]
        else:
            app_name = self.hs.config.email_app_name

        return app_name
