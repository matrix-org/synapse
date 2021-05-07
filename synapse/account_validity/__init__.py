# -*- coding: utf-8 -*-
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

from typing import TYPE_CHECKING, Any, List, Optional, Tuple

if TYPE_CHECKING:
    import synapse.events
    import synapse.server


class AccountValidity:
    def __init__(self, hs: "synapse.server.HomeServer"):
        self.modules = []  # type: List[Any]
        api = hs.get_module_api()

        for module, config in hs.config.account_validity_modules:
            self.modules.append(module(config=config, api=api))

    async def on_legacy_send_mail(self, user_id: str):
        """DEPRECATED: Function called when receiving a request on the deprecated
        /_matrix/client/unstable/account_validity/send_mail endpoint. Modules that don't
        reimplement the legacy email-based account validity feature should ignore this.
        If several modules implement this hook, only the first one (in the orders modules
        have been loaded at startup) gets called.

        Args:
            user_id: The user ID to send a renewal email to.

        Raises:
            NotImplementedError: No configured module implement this hook.
        """
        implemented = False
        for module in self.modules:
            if hasattr(module, "on_legacy_send_mail"):
                await module.on_legacy_send_mail(user_id)
                return

        if not implemented:
            raise NotImplementedError()

    async def on_legacy_renew(self, renewal_token: str) -> Tuple[bool, bool, int]:
        """DEPRECATED: Function called when receiving a request on the deprecated
        /_matrix/client/unstable/account_validity/renew endpoint. Modules that don't
        reimplement the legacy email-based account validity feature should ignore this.
        If several modules implement this hook, only the first one (in the orders modules
        have been loaded at startup) gets called.

        Args:
            renewal_token: The renewal token provided in the request.

        Raises:
            NotImplementedError: No configured module implement this hook.
        """
        implemented = False
        for module in self.modules:
            if hasattr(module, "on_legacy_renew"):
                return await module.on_legacy_renew(renewal_token)

        if not implemented:
            raise NotImplementedError()

    async def on_legacy_admin_request(self, request) -> int:
        """DEPRECATED: Function called when receiving a request on the deprecated
        /_synapse/admin/v1/account_validity/validity endpoint, after the requester has
        been identified as a server admin. Modules that don't reimplement the legacy
        email-based account validity feature should ignore this.
        If several modules implement this hook, only the first one (in the orders modules
        have been loaded at startup) gets called.

        Args:
            request: The admin request

        Raises:
            NotImplementedError: No configured module implement this hook.
        """
        implemented = False
        for module in self.modules:
            if hasattr(module, "on_legacy_admin_request"):
                return await module.on_legacy_admin_request(request)

        if not implemented:
            raise NotImplementedError()

    async def is_user_expired(self, user_id: str) -> bool:
        """Check whether the user is expired.

        Modules are expected to return either a boolean indicating whether the user is
        expired, or None if it was not able to figure it out.

        If a module returns None, the next module (in the order the modules have been
        loaded at startup) is called. If it returns a boolean, its value is used and the
        function returns.
        If none of the modules have been able to determine whether the user is expired,
        Synapse will consider them not expired to avoid locking them out of their account
        in case of a technical incident.

        Args:
            user_id: The user ID to check the expiration of.

        Returns:
            Whether the user has expired.
        """
        for module in self.modules:
            expired = await module.is_user_expired(user_id)  # type: Optional[bool]
            if expired is not None:
                return expired

        return False

    async def on_user_registration(self, user_id):
        """Function called after successfully registering a new user.

        Args:
            user_id: The Matrix ID of the newly registered user.
        """
        for module in self.modules:
            await module.on_user_registration(user_id)
