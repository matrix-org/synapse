# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
import re
from typing import TYPE_CHECKING, List, Optional, Pattern, Tuple

from synapse.appservice import (
    ApplicationService,
    ApplicationServiceState,
    AppServiceTransaction,
)
from synapse.config.appservice import load_appservices
from synapse.events import EventBase
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import DatabasePool
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.types import Connection
from synapse.types import JsonDict
from synapse.util import json_encoder

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)


def _make_exclusive_regex(
    services_cache: List[ApplicationService],
) -> Optional[Pattern]:
    # We precompile a regex constructed from all the regexes that the AS's
    # have registered for exclusive users.
    exclusive_user_regexes = [
        regex.pattern
        for service in services_cache
        for regex in service.get_exclusive_user_regexes()
    ]
    if exclusive_user_regexes:
        exclusive_user_regex = "|".join("(" + r + ")" for r in exclusive_user_regexes)
        exclusive_user_pattern = re.compile(
            exclusive_user_regex
        )  # type: Optional[Pattern]
    else:
        # We handle this case specially otherwise the constructed regex
        # will always match
        exclusive_user_pattern = None

    return exclusive_user_pattern


class ApplicationServiceWorkerStore(SQLBaseStore):
    def __init__(self, database: DatabasePool, db_conn: Connection, hs: "HomeServer"):
        self.services_cache = load_appservices(
            hs.hostname, hs.config.app_service_config_files
        )
        self.exclusive_user_regex = _make_exclusive_regex(self.services_cache)

        super().__init__(database, db_conn, hs)

    def get_app_services(self):
        return self.services_cache

    def get_if_app_services_interested_in_user(self, user_id: str) -> bool:
        """Check if the user is one associated with an app service (exclusively)"""
        if self.exclusive_user_regex:
            return bool(self.exclusive_user_regex.match(user_id))
        else:
            return False

    def get_app_service_by_user_id(self, user_id: str) -> Optional[ApplicationService]:
        """Retrieve an application service from their user ID.

        All application services have associated with them a particular user ID.
        There is no distinguishing feature on the user ID which indicates it
        represents an application service. This function allows you to map from
        a user ID to an application service.

        Args:
            user_id: The user ID to see if it is an application service.
        Returns:
            The application service or None.
        """
        for service in self.services_cache:
            if service.sender == user_id:
                return service
        return None

    def get_app_service_by_token(self, token: str) -> Optional[ApplicationService]:
        """Get the application service with the given appservice token.

        Args:
            token: The application service token.
        Returns:
            The application service or None.
        """
        for service in self.services_cache:
            if service.token == token:
                return service
        return None

    def get_app_service_by_id(self, as_id: str) -> Optional[ApplicationService]:
        """Get the application service with the given appservice ID.

        Args:
            as_id: The application service ID.
        Returns:
            The application service or None.
        """
        for service in self.services_cache:
            if service.id == as_id:
                return service
        return None


class ApplicationServiceStore(ApplicationServiceWorkerStore):
    # This is currently empty due to there not being any AS storage functions
    # that can't be run on the workers. Since this may change in future, and
    # to keep consistency with the other stores, we keep this empty class for
    # now.
    pass


class ApplicationServiceTransactionWorkerStore(
    ApplicationServiceWorkerStore, EventsWorkerStore
):
    async def get_appservices_by_state(
        self, state: ApplicationServiceState
    ) -> List[ApplicationService]:
        """Get a list of application services based on their state.

        Args:
            state: The state to filter on.
        Returns:
            A list of ApplicationServices, which may be empty.
        """
        results = await self.db_pool.simple_select_list(
            "application_services_state", {"state": state}, ["as_id"]
        )
        # NB: This assumes this class is linked with ApplicationServiceStore
        as_list = self.get_app_services()
        services = []

        for res in results:
            for service in as_list:
                if service.id == res["as_id"]:
                    services.append(service)
        return services

    async def get_appservice_state(
        self, service: ApplicationService
    ) -> Optional[ApplicationServiceState]:
        """Get the application service state.

        Args:
            service: The service whose state to set.
        Returns:
            An ApplicationServiceState or none.
        """
        result = await self.db_pool.simple_select_one(
            "application_services_state",
            {"as_id": service.id},
            ["state"],
            allow_none=True,
            desc="get_appservice_state",
        )
        if result:
            return result.get("state")
        return None

    async def set_appservice_state(
        self, service: ApplicationService, state: ApplicationServiceState
    ) -> None:
        """Set the application service state.

        Args:
            service: The service whose state to set.
            state: The connectivity state to apply.
        """
        await self.db_pool.simple_upsert(
            "application_services_state", {"as_id": service.id}, {"state": state}
        )

    async def create_appservice_txn(
        self,
        service: ApplicationService,
        events: List[EventBase],
        ephemeral: List[JsonDict],
    ) -> AppServiceTransaction:
        """Atomically creates a new transaction for this application service
        with the given list of events. Ephemeral events are NOT persisted to the
        database and are not resent if a transaction is retried.

        Args:
            service: The service who the transaction is for.
            events: A list of persistent events to put in the transaction.
            ephemeral: A list of ephemeral events to put in the transaction.

        Returns:
            A new transaction.
        """

        def _create_appservice_txn(txn):
            # work out new txn id (highest txn id for this service += 1)
            # The highest id may be the last one sent (in which case it is last_txn)
            # or it may be the highest in the txns list (which are waiting to be/are
            # being sent)
            last_txn_id = self._get_last_txn(txn, service.id)

            txn.execute(
                "SELECT MAX(txn_id) FROM application_services_txns WHERE as_id=?",
                (service.id,),
            )
            highest_txn_id = txn.fetchone()[0]
            if highest_txn_id is None:
                highest_txn_id = 0

            new_txn_id = max(highest_txn_id, last_txn_id) + 1

            # Insert new txn into txn table
            event_ids = json_encoder.encode([e.event_id for e in events])
            txn.execute(
                "INSERT INTO application_services_txns(as_id, txn_id, event_ids) "
                "VALUES(?,?,?)",
                (service.id, new_txn_id, event_ids),
            )
            return AppServiceTransaction(
                service=service, id=new_txn_id, events=events, ephemeral=ephemeral
            )

        return await self.db_pool.runInteraction(
            "create_appservice_txn", _create_appservice_txn
        )

    async def complete_appservice_txn(
        self, txn_id: int, service: ApplicationService
    ) -> None:
        """Completes an application service transaction.

        Args:
            txn_id: The transaction ID being completed.
            service: The application service which was sent this transaction.
        """
        txn_id = int(txn_id)

        def _complete_appservice_txn(txn):
            # Debugging query: Make sure the txn being completed is EXACTLY +1 from
            # what was there before. If it isn't, we've got problems (e.g. the AS
            # has probably missed some events), so whine loudly but still continue,
            # since it shouldn't fail completion of the transaction.
            last_txn_id = self._get_last_txn(txn, service.id)
            if (last_txn_id + 1) != txn_id:
                logger.error(
                    "appservice: Completing a transaction which has an ID > 1 from "
                    "the last ID sent to this AS. We've either dropped events or "
                    "sent it to the AS out of order. FIX ME. last_txn=%s "
                    "completing_txn=%s service_id=%s",
                    last_txn_id,
                    txn_id,
                    service.id,
                )

            # Set current txn_id for AS to 'txn_id'
            self.db_pool.simple_upsert_txn(
                txn,
                "application_services_state",
                {"as_id": service.id},
                {"last_txn": txn_id},
            )

            # Delete txn
            self.db_pool.simple_delete_txn(
                txn,
                "application_services_txns",
                {"txn_id": txn_id, "as_id": service.id},
            )

        await self.db_pool.runInteraction(
            "complete_appservice_txn", _complete_appservice_txn
        )

    async def get_oldest_unsent_txn(
        self, service: ApplicationService
    ) -> Optional[AppServiceTransaction]:
        """Get the oldest transaction which has not been sent for this service.

        Args:
            service: The app service to get the oldest txn.
        Returns:
            An AppServiceTransaction or None.
        """

        def _get_oldest_unsent_txn(txn):
            # Monotonically increasing txn ids, so just select the smallest
            # one in the txns table (we delete them when they are sent)
            txn.execute(
                "SELECT * FROM application_services_txns WHERE as_id=?"
                " ORDER BY txn_id ASC LIMIT 1",
                (service.id,),
            )
            rows = self.db_pool.cursor_to_dict(txn)
            if not rows:
                return None

            entry = rows[0]

            return entry

        entry = await self.db_pool.runInteraction(
            "get_oldest_unsent_appservice_txn", _get_oldest_unsent_txn
        )

        if not entry:
            return None

        event_ids = db_to_json(entry["event_ids"])

        events = await self.get_events_as_list(event_ids)

        return AppServiceTransaction(
            service=service, id=entry["txn_id"], events=events, ephemeral=[]
        )

    def _get_last_txn(self, txn, service_id: Optional[str]) -> int:
        txn.execute(
            "SELECT last_txn FROM application_services_state WHERE as_id=?",
            (service_id,),
        )
        last_txn_id = txn.fetchone()
        if last_txn_id is None or last_txn_id[0] is None:  # no row exists
            return 0
        else:
            return int(last_txn_id[0])  # select 'last_txn' col

    async def set_appservice_last_pos(self, pos: int) -> None:
        def set_appservice_last_pos_txn(txn):
            txn.execute(
                "UPDATE appservice_stream_position SET stream_ordering = ?", (pos,)
            )

        await self.db_pool.runInteraction(
            "set_appservice_last_pos", set_appservice_last_pos_txn
        )

    async def get_new_events_for_appservice(
        self, current_id: int, limit: int
    ) -> Tuple[int, List[EventBase]]:
        """Get all new events for an appservice"""

        def get_new_events_for_appservice_txn(txn):
            sql = (
                "SELECT e.stream_ordering, e.event_id"
                " FROM events AS e"
                " WHERE"
                " (SELECT stream_ordering FROM appservice_stream_position)"
                "     < e.stream_ordering"
                " AND e.stream_ordering <= ?"
                " ORDER BY e.stream_ordering ASC"
                " LIMIT ?"
            )

            txn.execute(sql, (current_id, limit))
            rows = txn.fetchall()

            upper_bound = current_id
            if len(rows) == limit:
                upper_bound = rows[-1][0]

            return upper_bound, [row[1] for row in rows]

        upper_bound, event_ids = await self.db_pool.runInteraction(
            "get_new_events_for_appservice", get_new_events_for_appservice_txn
        )

        events = await self.get_events_as_list(event_ids)

        return upper_bound, events

    async def get_type_stream_id_for_appservice(
        self, service: ApplicationService, type: str
    ) -> int:
        if type not in ("read_receipt", "presence"):
            raise ValueError(
                "Expected type to be a valid application stream id type, got %s"
                % (type,)
            )

        def get_type_stream_id_for_appservice_txn(txn):
            stream_id_type = "%s_stream_id" % type
            txn.execute(
                # We do NOT want to escape `stream_id_type`.
                "SELECT %s FROM application_services_state WHERE as_id=?"
                % stream_id_type,
                (service.id,),
            )
            last_stream_id = txn.fetchone()
            if last_stream_id is None or last_stream_id[0] is None:  # no row exists
                return 0
            else:
                return int(last_stream_id[0])

        return await self.db_pool.runInteraction(
            "get_type_stream_id_for_appservice", get_type_stream_id_for_appservice_txn
        )

    async def set_type_stream_id_for_appservice(
        self, service: ApplicationService, type: str, pos: Optional[int]
    ) -> None:
        if type not in ("read_receipt", "presence"):
            raise ValueError(
                "Expected type to be a valid application stream id type, got %s"
                % (type,)
            )

        def set_type_stream_id_for_appservice_txn(txn):
            stream_id_type = "%s_stream_id" % type
            txn.execute(
                "UPDATE application_services_state SET %s = ? WHERE as_id=?"
                % stream_id_type,
                (pos, service.id),
            )

        await self.db_pool.runInteraction(
            "set_type_stream_id_for_appservice", set_type_stream_id_for_appservice_txn
        )


class ApplicationServiceTransactionStore(ApplicationServiceTransactionWorkerStore):
    # This is currently empty due to there not being any AS storage functions
    # that can't be run on the workers. Since this may change in future, and
    # to keep consistency with the other stores, we keep this empty class for
    # now.
    pass
