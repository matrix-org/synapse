# -*- coding: utf-8 -*-
# Copyright 2020 Matrix.org Foundation C.I.C.
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
import json
from typing import Any, Dict, Optional, Union

import synapse.util.stringutils as stringutils
from synapse.api.errors import StoreError, SynapseError
from synapse.storage._base import SQLBaseStore


class UIAuthStore(SQLBaseStore):
    """
    Manage user interactive authentication sessions.
    """

    # TODO Expire old entries.
    SESSION_EXPIRE_MS = 48 * 60 * 60 * 1000

    async def create_session(
        self, clientdict: Dict[str, Any], uri: str, method: str, description: str,
    ) -> str:
        """
        Creates a new user interactive authentication session.

        The session can be used to track data across multiple requests, e.g. for
        interactive authentication.
        """
        # TODO How to generate the session ID.
        session_id = stringutils.random_string(24)

        await self.db.simple_insert(
            table="ui_auth_sessions",
            values={
                "session_id": session_id,
                "clientdict": json.dumps(clientdict),
                "uri": uri,
                "method": method,
                "description": description,
                "serverdict": "{}",
                # TODO Keep this up-to-date.
                "last_used": self.hs.get_clock().time_msec(),
            },
        )

        return session_id

    async def get_session(self, session_id: str):
        """Retrieve a UI auth session.

        Args:
            session_id: The ID of the session.
        Returns:
            defer.Deferred for a dict containing the device information.
        Raises:
            SynapseError: if the session is not found.
        """
        try:
            result = await self.db.simple_select_one(
                table="ui_auth_sessions",
                keyvalues={"session_id": session_id},
                retcols=("clientdict", "uri", "method", "description"),
                desc="get_session",
            )
        except StoreError:
            raise SynapseError(400, "Unknown session ID: %s" % session_id)

        result["clientdict"] = json.loads(result["clientdict"])

        return result

    async def mark_stage_complete(
        self,
        session_id: str,
        stage_type: str,
        identity: Union[str, bool, Dict[str, any]],
    ):
        """
        Mark a session stage as completed.

        Args:
            session_id: The ID of the corresponding session.
            stage_type: The completed stage type.
            identity: The identity authenticated by the stage.
        """
        await self.db.simple_upsert(
            table="ui_auth_sessions_credentials",
            keyvalues={"session_id": session_id, "stage_type": stage_type},
            values={"identity": json.dumps(identity)},
            desc="mark_stage_complete",
        )

    async def get_completed_stages(
        self, session_id: str
    ) -> Dict[str, Union[str, bool, Dict[str, Any]]]:
        """
        Retrieve the completed stages of a UI authentication session.

        Args:
            session_id: The ID of the session.
        Returns:
            The completed stages mapped to the user which completed that stage.
        Raises:
            StoreError: if the session is not found.
        """
        results = {}
        for row in await self.db.simple_select_list(
            table="ui_auth_sessions_credentials",
            keyvalues={"session_id": session_id},
            retcols=("stage_type", "identity"),
            desc="get_completed_stages",
        ):
            results[row["stage_type"]] = json.loads(row["identity"])

        return results

    async def set_session_data(self, session_id: str, key: str, value: Any):
        """
        Store a key-value pair into the sessions data associated with this
        request. This data is stored server-side and cannot be modified by
        the client.

        Args:
            session_id: The ID of this session as returned from check_auth
            key: The key to store the data under
            value: The data to store
        """
        result = await self.db.simple_select_one(
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            retcols=("serverdict",),
            desc="set_server_data_select",
        )

        serverdict = json.loads(result["serverdict"])
        serverdict[key] = value

        await self.db.simple_update_one(
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            updatevalues={"serverdict": json.dumps(serverdict)},
            desc="set_server_data_update",
        )

    async def get_session_data(
        self, session_id: str, key: str, default: Optional[Any] = None
    ):
        """
        Retrieve data stored with set_session_data

        Args:
            session_id: The ID of this session as returned from check_auth
            key: The key to store the data under
            default: Value to return if the key has not been set
        """
        result = await self.db.simple_select_one(
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            retcols=("serverdict",),
            desc="get_server_data",
        )

        serverdict = json.loads(result["serverdict"])

        return serverdict.get(key, default)
