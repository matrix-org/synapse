# -*- coding: utf-8 -*-
# Copyright 2019 Matrix.org Foundation C.I.C
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

import enum
import uuid
from collections import defaultdict

import attr

from synapse.storage._base import SQLBaseStore


class TokenState(enum.Enum):
    VALID = enum.auto()
    EXPIRED = enum.auto()
    NOT_YET_ACTIVE = enum.auto()
    NON_EXISTANT = enum.auto()


@attr.s
class TokenLookupResult(object):
    admin_token = attr.ib()
    permissions = attr.ib(
        default=attr.Factory(lambda: defaultdict(lambda: defaultdict(lambda: False)))
    )
    token_state = attr.ib(type=TokenState, default=TokenState.NON_EXISTANT)


class AdminTokenWorkerStore(SQLBaseStore):
    async def get_permissions_for_token(self, admin_token: str) -> TokenLookupResult:
        """
        Get a token and its permissions.

        Args:
            admin_token: The admin token to look up permissions for:
        """
        result = TokenLookupResult(admin_token=admin_token)

        token = await self._simple_select_one(
            "admin_tokens",
            {"admin_token": admin_token},
            ["admin_token", "valid_from", "valid_until"],
            allow_none=True,
        )

        # Token does not exist
        if token is None:
            result.token_state = TokenState.NON_EXISTANT
            return result

        elif token["valid_from"] > self.hs.get_reactor().seconds():
            result.token_state = TokenState.NOT_YET_ACTIVE
            return result

        # Token is expired
        elif token["valid_until"] < self.hs.get_reactor().seconds():
            result.token_state = TokenState.EXPIRED
            return result

        permissions = await self._simple_select_list(
            "admin_token_permissions",
            {"admin_token": token["admin_token"]},
            ["endpoint", "action", "allowed"],
        )

        for permission in permissions:
            if permission["allowed"]:
                result.permissions[permission["endpoint"]][permission["action"]] = True

        result.token_state = TokenState.VALID
        return result

    async def create_admin_token(
        self, valid_until: int, creator: str, description: str
    ) -> str:
        """
        Create a new admin token and return it.

        Args:
            valid_until: Token's end validity, in seconds since the epoch.
            creator: mxid of the creating user, if applicable.
            description: A description of the token's use.

        Returns:
            The admin token.
        """
        now = int(self.hs.get_reactor().seconds())

        if valid_until < now:
            raise ValueError("Can't end validity in the past")

        token_value = self.hs.get_secrets().token_bytes(16)
        token_uuid = str(uuid.UUID(bytes=token_value))

        await self._simple_insert(
            "admin_tokens",
            {
                "admin_token": token_uuid,
                "valid_from": now,
                "valid_until": valid_until,
                "created_by": creator,
                "description": description,
            },
        )

        return token_uuid

    async def set_permission_for_token(
        self, admin_token: str, endpoint: str, action: str, allowed: bool
    ) -> bool:
        """
        Set a permission on a token for a given endpoint and action.

        Args:
            admin_token
            endpoint: The endpoint token to grant permission to.
            action: The action to grant permission to do.
            allowed: Whether this should be granting permission, or removing it.

        Returns:
            True
        """

        await self._simple_upsert(
            "admin_token_permissions",
            {"admin_token": admin_token, "endpoint": endpoint, "action": action},
            {"allowed": allowed},
        )

        return True
