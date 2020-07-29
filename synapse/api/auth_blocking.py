# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

from twisted.internet import defer

from synapse.api.constants import LimitBlockingTypes, UserTypes
from synapse.api.errors import Codes, ResourceLimitError
from synapse.config.server import is_threepid_reserved

logger = logging.getLogger(__name__)


class AuthBlocking(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()

        self._server_notices_mxid = hs.config.server_notices_mxid
        self._hs_disabled = hs.config.hs_disabled
        self._hs_disabled_message = hs.config.hs_disabled_message
        self._admin_contact = hs.config.admin_contact
        self._max_mau_value = hs.config.max_mau_value
        self._limit_usage_by_mau = hs.config.limit_usage_by_mau
        self._mau_limits_reserved_threepids = hs.config.mau_limits_reserved_threepids

    @defer.inlineCallbacks
    def check_auth_blocking(self, user_id=None, threepid=None, user_type=None):
        """Checks if the user should be rejected for some external reason,
        such as monthly active user limiting or global disable flag

        Args:
            user_id(str|None): If present, checks for presence against existing
                MAU cohort

            threepid(dict|None): If present, checks for presence against configured
                reserved threepid. Used in cases where the user is trying register
                with a MAU blocked server, normally they would be rejected but their
                threepid is on the reserved list. user_id and
                threepid should never be set at the same time.

            user_type(str|None): If present, is used to decide whether to check against
                certain blocking reasons like MAU.
        """

        # Never fail an auth check for the server notices users or support user
        # This can be a problem where event creation is prohibited due to blocking
        if user_id is not None:
            if user_id == self._server_notices_mxid:
                return
            if (yield self.store.is_support_user(user_id)):
                return

        if self._hs_disabled:
            raise ResourceLimitError(
                403,
                self._hs_disabled_message,
                errcode=Codes.RESOURCE_LIMIT_EXCEEDED,
                admin_contact=self._admin_contact,
                limit_type=LimitBlockingTypes.HS_DISABLED,
            )
        if self._limit_usage_by_mau is True:
            assert not (user_id and threepid)

            # If the user is already part of the MAU cohort or a trial user
            if user_id:
                timestamp = yield self.store.user_last_seen_monthly_active(user_id)
                if timestamp:
                    return

                is_trial = yield self.store.is_trial_user(user_id)
                if is_trial:
                    return
            elif threepid:
                # If the user does not exist yet, but is signing up with a
                # reserved threepid then pass auth check
                if is_threepid_reserved(self._mau_limits_reserved_threepids, threepid):
                    return
            elif user_type == UserTypes.SUPPORT:
                # If the user does not exist yet and is of type "support",
                # allow registration. Support users are excluded from MAU checks.
                return
            # Else if there is no room in the MAU bucket, bail
            current_mau = yield self.store.get_monthly_active_count()
            if current_mau >= self._max_mau_value:
                raise ResourceLimitError(
                    403,
                    "Monthly Active User Limit Exceeded",
                    admin_contact=self._admin_contact,
                    errcode=Codes.RESOURCE_LIMIT_EXCEEDED,
                    limit_type=LimitBlockingTypes.MONTHLY_ACTIVE_USER,
                )
