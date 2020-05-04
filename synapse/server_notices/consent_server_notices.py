# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from six import iteritems, string_types

from synapse.api.errors import SynapseError
from synapse.api.urls import ConsentURIBuilder
from synapse.config import ConfigError
from synapse.types import get_localpart_from_id

logger = logging.getLogger(__name__)


class ConsentServerNotices(object):
    """Keeps track of whether we need to send users server_notices about
    privacy policy consent, and sends one if we do.
    """

    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer):
        """
        self._server_notices_manager = hs.get_server_notices_manager()
        self._store = hs.get_datastore()

        self._users_in_progress = set()

        self._current_consent_version = hs.config.user_consent_version
        self._server_notice_content = hs.config.user_consent_server_notice_content
        self._send_to_guests = hs.config.user_consent_server_notice_to_guests

        if self._server_notice_content is not None:
            if not self._server_notices_manager.is_enabled():
                raise ConfigError(
                    "user_consent configuration requires server notices, but "
                    "server notices are not enabled."
                )
            if "body" not in self._server_notice_content:
                raise ConfigError(
                    "user_consent server_notice_consent must contain a 'body' key."
                )

            self._consent_uri_builder = ConsentURIBuilder(hs.config)

    async def maybe_send_server_notice_to_user(self, user_id):
        """Check if we need to send a notice to this user, and does so if so

        Args:
            user_id (str): user to check

        Returns:
            Deferred
        """
        if self._server_notice_content is None:
            # not enabled
            return

        # make sure we don't send two messages to the same user at once
        if user_id in self._users_in_progress:
            return
        self._users_in_progress.add(user_id)
        try:
            u = await self._store.get_user_by_id(user_id)

            if u["is_guest"] and not self._send_to_guests:
                # don't send to guests
                return

            if u["consent_version"] == self._current_consent_version:
                # user has already consented
                return

            if u["consent_server_notice_sent"] == self._current_consent_version:
                # we've already sent a notice to the user
                return

            # need to send a message.
            try:
                consent_uri = self._consent_uri_builder.build_user_consent_uri(
                    get_localpart_from_id(user_id)
                )
                content = copy_with_str_subst(
                    self._server_notice_content, {"consent_uri": consent_uri}
                )
                await self._server_notices_manager.send_notice(user_id, content)
                await self._store.user_set_consent_server_notice_sent(
                    user_id, self._current_consent_version
                )
            except SynapseError as e:
                logger.error("Error sending server notice about user consent: %s", e)
        finally:
            self._users_in_progress.remove(user_id)


def copy_with_str_subst(x, substitutions):
    """Deep-copy a structure, carrying out string substitions on any strings

    Args:
        x (object): structure to be copied
        substitutions (object): substitutions to be made - passed into the
            string '%' operator

    Returns:
        copy of x
    """
    if isinstance(x, string_types):
        return x % substitutions
    if isinstance(x, dict):
        return {k: copy_with_str_subst(v, substitutions) for (k, v) in iteritems(x)}
    if isinstance(x, (list, tuple)):
        return [copy_with_str_subst(y) for y in x]

    # assume it's uninterested and can be shallow-copied.
    return x
