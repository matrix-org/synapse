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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Pattern, Tuple, cast

from synapse.appservice import (
    ApplicationService,
    ApplicationServiceState,
    AppServiceTransaction,
    TransactionOneTimeKeyCounts,
    TransactionUnusedFallbackKeys,
)
from synapse.config.appservice import load_appservices
from synapse.events import EventBase
from synapse.storage._base import db_to_json
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.databases.main.roommember import RoomMemberWorkerStore
from synapse.storage.types import Cursor
from synapse.storage.util.sequence import build_sequence_generator
from synapse.types import DeviceListUpdates, JsonDict
from synapse.util import json_encoder
from synapse.util.caches.descriptors import _CacheContext, cached

if TYPE_CHECKING:
    from synapse.server import HomeServer

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
        exclusive_user_pattern: Optional[Pattern] = re.compile(exclusive_user_regex)
    else:
        # We handle this case specially otherwise the constructed regex
        # will always match
        exclusive_user_pattern = None

    return exclusive_user_pattern


class ApplicationServiceWorkerStore(RoomMemberWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        self.services_cache = load_appservices(
            hs.hostname, hs.config.appservice.app_service_config_files
        )
        self.exclusive_user_regex = _make_exclusive_regex(self.services_cache)

        def get_max_as_txn_id(txn: Cursor) -> int:
            logger.warning("Falling back to slow query, you should port to postgres")
            txn.execute(
                "SELECT COALESCE(max(txn_id), 0) FROM application_services_txns"
            )
            return cast(Tuple[int], txn.fetchone())[0]

        self._as_txn_seq_gen = build_sequence_generator(
            db_conn,
            database.engine,
            get_max_as_txn_id,
            "application_services_txn_id_seq",
            table="application_services_txns",
            id_column="txn_id",
        )

        super().__init__(database, db_conn, hs)

    def get_app_services(self) -> List[ApplicationService]:
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

    @cached(iterable=True, cache_context=True)
    async def get_app_service_users_in_room(
        self,
        room_id: str,
        app_service: "ApplicationService",
        cache_context: _CacheContext,
    ) -> List[str]:
        """
        Get all users in a room that the appservice controls.

        Args:
            room_id: The room to check in.
            app_service: The application service to check interest/control against

        Returns:
            List of user IDs that the appservice controls.
        """
        # We can use `get_local_users_in_room(...)` here because an application service
        # can only be interested in local users of the server it's on (ignore any remote
        # users that might match the user namespace regex).
        local_users_in_room = await self.get_local_users_in_room(
            room_id, on_invalidate=cache_context.invalidate
        )
        return list(filter(app_service.is_interested_in_user, local_users_in_room))


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
            "application_services_state", {"state": state.value}, ["as_id"]
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
            service: The service whose state to get.
        Returns:
            An ApplicationServiceState, or None if we have yet to attempt any
            transactions to the AS.
        """
        # if we have created transactions for this AS but not yet attempted to send
        # them, we will have a row in the table with state=NULL (recording the stream
        # positions we have processed up to).
        #
        # On the other hand, if we have yet to create any transactions for this AS at
        # all, then there will be no row for the AS.
        #
        # In either case, we return None to indicate "we don't yet know the state of
        # this AS".
        result = await self.db_pool.simple_select_one_onecol(
            "application_services_state",
            {"as_id": service.id},
            retcol="state",
            allow_none=True,
            desc="get_appservice_state",
        )
        if result:
            return ApplicationServiceState(result)
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
            "application_services_state", {"as_id": service.id}, {"state": state.value}
        )

    async def create_appservice_txn(
        self,
        service: ApplicationService,
        events: List[EventBase],
        ephemeral: List[JsonDict],
        to_device_messages: List[JsonDict],
        one_time_key_counts: TransactionOneTimeKeyCounts,
        unused_fallback_keys: TransactionUnusedFallbackKeys,
        device_list_summary: DeviceListUpdates,
    ) -> AppServiceTransaction:
        """Atomically creates a new transaction for this application service
        with the given list of events. Ephemeral events are NOT persisted to the
        database and are not resent if a transaction is retried.

        Args:
            service: The service who the transaction is for.
            events: A list of persistent events to put in the transaction.
            ephemeral: A list of ephemeral events to put in the transaction.
            to_device_messages: A list of to-device messages to put in the transaction.
            one_time_key_counts: Counts of remaining one-time keys for relevant
                appservice devices in the transaction.
            unused_fallback_keys: Lists of unused fallback keys for relevant
                appservice devices in the transaction.
            device_list_summary: The device list summary to include in the transaction.

        Returns:
            A new transaction.
        """

        def _create_appservice_txn(txn: LoggingTransaction) -> AppServiceTransaction:
            new_txn_id = self._as_txn_seq_gen.get_next_id_txn(txn)

            # Insert new txn into txn table
            event_ids = json_encoder.encode([e.event_id for e in events])
            txn.execute(
                "INSERT INTO application_services_txns(as_id, txn_id, event_ids) "
                "VALUES(?,?,?)",
                (service.id, new_txn_id, event_ids),
            )
            return AppServiceTransaction(
                service=service,
                id=new_txn_id,
                events=events,
                ephemeral=ephemeral,
                to_device_messages=to_device_messages,
                one_time_key_counts=one_time_key_counts,
                unused_fallback_keys=unused_fallback_keys,
                device_list_summary=device_list_summary,
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

        def _complete_appservice_txn(txn: LoggingTransaction) -> None:
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

        def _get_oldest_unsent_txn(
            txn: LoggingTransaction,
        ) -> Optional[Dict[str, Any]]:
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

        # TODO: to-device messages, one-time key counts, device list summaries and unused
        #       fallback keys are not yet populated for catch-up transactions.
        #       We likely want to populate those for reliability.
        return AppServiceTransaction(
            service=service,
            id=entry["txn_id"],
            events=events,
            ephemeral=[],
            to_device_messages=[],
            one_time_key_counts={},
            unused_fallback_keys={},
            device_list_summary=DeviceListUpdates(),
        )

    async def get_appservice_last_pos(self) -> int:
        """
        Get the last stream ordering position for the appservice process.
        """

        return await self.db_pool.simple_select_one_onecol(
            table="appservice_stream_position",
            retcol="stream_ordering",
            keyvalues={},
            desc="get_appservice_last_pos",
        )

    async def set_appservice_last_pos(self, pos: int) -> None:
        """
        Set the last stream ordering position for the appservice process.
        """

        await self.db_pool.simple_update_one(
            table="appservice_stream_position",
            keyvalues={},
            updatevalues={"stream_ordering": pos},
            desc="set_appservice_last_pos",
        )

    async def get_type_stream_id_for_appservice(
        self, service: ApplicationService, type: str
    ) -> int:
        if type not in ("read_receipt", "presence", "to_device", "device_list"):
            raise ValueError(
                "Expected type to be a valid application stream id type, got %s"
                % (type,)
            )

        def get_type_stream_id_for_appservice_txn(txn: LoggingTransaction) -> int:
            stream_id_type = "%s_stream_id" % type
            txn.execute(
                # We do NOT want to escape `stream_id_type`.
                "SELECT %s FROM application_services_state WHERE as_id=?"
                % stream_id_type,
                (service.id,),
            )
            last_stream_id = txn.fetchone()
            if last_stream_id is None or last_stream_id[0] is None:  # no row exists
                # Stream tokens always start from 1, to avoid foot guns around `0` being falsey.
                return 1
            else:
                return int(last_stream_id[0])

        return await self.db_pool.runInteraction(
            "get_type_stream_id_for_appservice", get_type_stream_id_for_appservice_txn
        )

    async def set_appservice_stream_type_pos(
        self, service: ApplicationService, stream_type: str, pos: Optional[int]
    ) -> None:
        if stream_type not in ("read_receipt", "presence", "to_device", "device_list"):
            raise ValueError(
                "Expected type to be a valid application stream id type, got %s"
                % (stream_type,)
            )

        # this may be the first time that we're recording any state for this AS, so
        # we don't yet know if a row for it exists; hence we have to upsert here.
        await self.db_pool.simple_upsert(
            table="application_services_state",
            keyvalues={"as_id": service.id},
            values={f"{stream_type}_stream_id": pos},
            # no need to lock when emulating upsert: as_id is a unique key
            lock=False,
            desc="set_appservice_stream_type_pos",
        )


class ApplicationServiceTransactionStore(ApplicationServiceTransactionWorkerStore):
    # This is currently empty due to there not being any AS storage functions
    # that can't be run on the workers. Since this may change in future, and
    # to keep consistency with the other stores, we keep this empty class for
    # now.
    pass
