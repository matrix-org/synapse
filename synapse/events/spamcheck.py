# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd.
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


class SpamChecker(object):
    def __init__(self, hs):
        self.spam_checker = None

        module = None
        config = None
        try:
            module, config = hs.config.spam_checker
        except:
            pass

        if module is not None:
            self.spam_checker = module(config=config)

    def check_event_for_spam(self, event):
        """Checks if a given event is considered "spammy" by this server.

        If the server considers an event spammy, then it will be rejected if
        sent by a local user. If it is sent by a user on another server, then
        users receive a blank event.

        Args:
            event (synapse.events.EventBase): the event to be checked

        Returns:
            bool: True if the event is spammy.
        """
        if self.spam_checker is None:
            return False

        return self.spam_checker.check_event_for_spam(event)

    def user_may_invite(self, userid, roomid):
        """Checks if a given user may send an invite

        If this method returns false, the invite will be rejected.

        Args:
            userid (string): The sender's user ID

        Returns:
            bool: True if the user may send an invite, otherwise False
        """
        if self.spam_checker is None:
            return True

        return self.spam_checker.user_may_invite(userid, roomid)
