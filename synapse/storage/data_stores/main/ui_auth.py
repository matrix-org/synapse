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

import attr

import synapse.util.stringutils as stringutils
from synapse.api.errors import StoreError
from synapse.storage._base import SQLBaseStore
from synapse.types import JsonDict


@attr.s
class UIAuthSessionData:
    session_id = attr.ib(type=str)
    # The dictionary from the client root level, not the 'auth' key.
    clientdict = attr.ib(type=JsonDict)
    # The URI and method the session was intiatied with. These are checked at
    # each stage of the authentication to ensure that the asked for operation
    # has not changed.
    uri = attr.ib(type=str)
    method = attr.ib(type=str)
    # A string description of the operation that the current authentication is
    # authorising.
    description = attr.ib(type=str)


class UIAuthWorkerStore(SQLBaseStore):
    """
    Manage user interactive authentication sessions.
    """

    async def create_ui_auth_session(
        self, clientdict: JsonDict, uri: str, method: str, description: str,
    ) -> UIAuthSessionData:
        """
        Creates a new user interactive authentication session.

        The session can be used to track the stages necessary to authenticate a
        user across multiple HTTP requests.

        Args:
            clientdict:
                The dictionary from the client root level, not the 'auth' key.
            uri:
                The URI this session was initiated with, this is checked at each
                stage of the authentication to ensure that the asked for
                operation has not changed.
            method:
                The method this session was initiated with, this is checked at each
                stage of the authentication to ensure that the asked for
                operation has not changed.
            description:
                A string description of the operation that the current
                authentication is authorising.
        Returns:
            The newly created session.
        Raises:
            StoreError if a unique session ID cannot be generated.
        """
        # The clientdict gets stored as JSON.
        clientdict_json = json.dumps(clientdict)

        # autogen a session ID and try to create it. We may clash, so just
        # try a few times till one goes through, giving up eventually.
        attempts = 0
        while attempts < 5:
            session_id = stringutils.random_string(24)

            try:
                await self.db.simple_insert(
                    table="ui_auth_sessions",
                    values={
                        "session_id": session_id,
                        "clientdict": clientdict_json,
                        "uri": uri,
                        "method": method,
                        "description": description,
                        "serverdict": "{}",
                        "creation_time": self.hs.get_clock().time_msec(),
                    },
                    desc="create_ui_auth_session",
                )
                return UIAuthSessionData(
                    session_id, clientdict, uri, method, description
                )
            except self.db.engine.module.IntegrityError:
                attempts += 1
        raise StoreError(500, "Couldn't generate a session ID.")

    async def get_ui_auth_session(self, session_id: str) -> UIAuthSessionData:
        """Retrieve a UI auth session.

        Args:
            session_id: The ID of the session.
        Returns:
            A dict containing the device information.
        Raises:
            StoreError if the session is not found.
        """
        result = await self.db.simple_select_one(
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            retcols=("clientdict", "uri", "method", "description"),
            desc="get_ui_auth_session",
        )

        result["clientdict"] = json.loads(result["clientdict"])

        return UIAuthSessionData(session_id, **result)

    async def mark_ui_auth_stage_complete(
        self, session_id: str, stage_type: str, result: Union[str, bool, JsonDict],
    ):
        """
        Mark a session stage as completed.

        Args:
            session_id: The ID of the corresponding session.
            stage_type: The completed stage type.
            result: The result of the stage verification.
        Raises:
            StoreError if the session cannot be found.
        """
        # Add (or update) the results of the current stage to the database.
        #
        # Note that we need to allow for the same stage to complete multiple
        # times here so that registration is idempotent.
        try:
            await self.db.simple_upsert(
                table="ui_auth_sessions_credentials",
                keyvalues={"session_id": session_id, "stage_type": stage_type},
                values={"result": json.dumps(result)},
                desc="mark_ui_auth_stage_complete",
            )
        except self.db.engine.module.IntegrityError:
            raise StoreError(400, "Unknown session ID: %s" % (session_id,))

    async def get_completed_ui_auth_stages(
        self, session_id: str
    ) -> Dict[str, Union[str, bool, JsonDict]]:
        """
        Retrieve the completed stages of a UI authentication session.

        Args:
            session_id: The ID of the session.
        Returns:
            The completed stages mapped to the result of the verification of
            that auth-type.
        """
        results = {}
        for row in await self.db.simple_select_list(
            table="ui_auth_sessions_credentials",
            keyvalues={"session_id": session_id},
            retcols=("stage_type", "result"),
            desc="get_completed_ui_auth_stages",
        ):
            results[row["stage_type"]] = json.loads(row["result"])

        return results

    async def set_ui_auth_clientdict(
        self, session_id: str, clientdict: JsonDict
    ) -> None:
        """
        Store an updated clientdict for a given session ID.

        Args:
            session_id: The ID of this session as returned from check_auth
            clientdict:
                The dictionary from the client root level, not the 'auth' key.
        """
        # The clientdict gets stored as JSON.
        clientdict_json = json.dumps(clientdict)

        self.db.simple_update_one(
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            updatevalues={"clientdict": clientdict_json},
            desc="set_ui_auth_client_dict",
        )

    async def set_ui_auth_session_data(self, session_id: str, key: str, value: Any):
        """
        Store a key-value pair into the sessions data associated with this
        request. This data is stored server-side and cannot be modified by
        the client.

        Args:
            session_id: The ID of this session as returned from check_auth
            key: The key to store the data under
            value: The data to store
        Raises:
            StoreError if the session cannot be found.
        """
        await self.db.runInteraction(
            "set_ui_auth_session_data",
            self._set_ui_auth_session_data_txn,
            session_id,
            key,
            value,
        )

    def _set_ui_auth_session_data_txn(self, txn, session_id: str, key: str, value: Any):
        # Get the current value.
        result = self.db.simple_select_one_txn(
            txn,
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            retcols=("serverdict",),
        )

        # Update it and add it back to the database.
        serverdict = json.loads(result["serverdict"])
        serverdict[key] = value

        self.db.simple_update_one_txn(
            txn,
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            updatevalues={"serverdict": json.dumps(serverdict)},
        )

    async def get_ui_auth_session_data(
        self, session_id: str, key: str, default: Optional[Any] = None
    ) -> Any:
        """
        Retrieve data stored with set_session_data

        Args:
            session_id: The ID of this session as returned from check_auth
            key: The key to store the data under
            default: Value to return if the key has not been set
        Raises:
            StoreError if the session cannot be found.
        """
        result = await self.db.simple_select_one(
            table="ui_auth_sessions",
            keyvalues={"session_id": session_id},
            retcols=("serverdict",),
            desc="get_ui_auth_session_data",
        )

        serverdict = json.loads(result["serverdict"])

        return serverdict.get(key, default)


class UIAuthStore(UIAuthWorkerStore):
    def delete_old_ui_auth_sessions(self, expiration_time: int):
        """
        Remove sessions which were last used earlier than the expiration time.

        Args:
            expiration_time: The latest time that is still considered valid.
                This is an epoch time in milliseconds.

        """
        return self.db.runInteraction(
            "delete_old_ui_auth_sessions",
            self._delete_old_ui_auth_sessions_txn,
            expiration_time,
        )

    def _delete_old_ui_auth_sessions_txn(self, txn, expiration_time: int):
        # Get the expired sessions.
        sql = "SELECT session_id FROM ui_auth_sessions WHERE creation_time <= ?"
        txn.execute(sql, [expiration_time])
        session_ids = [r[0] for r in txn.fetchall()]

        # Delete the corresponding completed credentials.
        self.db.simple_delete_many_txn(
            txn,
            table="ui_auth_sessions_credentials",
            column="session_id",
            iterable=session_ids,
            keyvalues={},
        )

        # Finally, delete the sessions.
        self.db.simple_delete_many_txn(
            txn,
            table="ui_auth_sessions",
            column="session_id",
            iterable=session_ids,
            keyvalues={},
        )
