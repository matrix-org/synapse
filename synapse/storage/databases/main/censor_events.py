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
from typing import TYPE_CHECKING

from synapse.events.utils import prune_event_dict
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import DatabasePool
from synapse.storage.databases.main.cache import CacheInvalidationWorkerStore
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.util import json_encoder

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class CensorEventsStore(EventsWorkerStore, CacheInvalidationWorkerStore, SQLBaseStore):
    def __init__(self, database: DatabasePool, db_conn, hs: "HomeServer"):
        super().__init__(database, db_conn, hs)

        if (
            hs.config.run_background_tasks
            and self.hs.config.redaction_retention_period is not None
        ):
            hs.get_clock().looping_call(self._censor_redactions, 5 * 60 * 1000)

    @wrap_as_background_process("_censor_redactions")
    async def _censor_redactions(self):
        """Censors all redactions older than the configured period that haven't
        been censored yet.

        By censor we mean update the event_json table with the redacted event.
        """

        if self.hs.config.redaction_retention_period is None:
            return

        if not (
            await self.db_pool.updates.has_completed_background_update(
                "redactions_have_censored_ts_idx"
            )
        ):
            # We don't want to run this until the appropriate index has been
            # created.
            return

        before_ts = self._clock.time_msec() - self.hs.config.redaction_retention_period

        # We fetch all redactions that:
        #   1. point to an event we have,
        #   2. has a received_ts from before the cut off, and
        #   3. we haven't yet censored.
        #
        # This is limited to 100 events to ensure that we don't try and do too
        # much at once. We'll get called again so this should eventually catch
        # up.
        sql = """
            SELECT redactions.event_id, redacts FROM redactions
            LEFT JOIN events AS original_event ON (
                redacts = original_event.event_id
            )
            WHERE NOT have_censored
            AND redactions.received_ts <= ?
            ORDER BY redactions.received_ts ASC
            LIMIT ?
        """

        rows = await self.db_pool.execute(
            "_censor_redactions_fetch", None, sql, before_ts, 100
        )

        updates = []

        for redaction_id, event_id in rows:
            redaction_event = await self.get_event(redaction_id, allow_none=True)
            original_event = await self.get_event(
                event_id, allow_rejected=True, allow_none=True
            )

            # The SQL above ensures that we have both the redaction and
            # original event, so if the `get_event` calls return None it
            # means that the redaction wasn't allowed. Either way we know that
            # the result won't change so we mark the fact that we've checked.
            if (
                redaction_event
                and original_event
                and original_event.internal_metadata.is_redacted()
            ):
                # Redaction was allowed
                pruned_json = json_encoder.encode(
                    prune_event_dict(
                        original_event.room_version, original_event.get_dict()
                    )
                )
            else:
                # Redaction wasn't allowed
                pruned_json = None

            updates.append((redaction_id, event_id, pruned_json))

        def _update_censor_txn(txn):
            for redaction_id, event_id, pruned_json in updates:
                if pruned_json:
                    self._censor_event_txn(txn, event_id, pruned_json)

                self.db_pool.simple_update_one_txn(
                    txn,
                    table="redactions",
                    keyvalues={"event_id": redaction_id},
                    updatevalues={"have_censored": True},
                )

        await self.db_pool.runInteraction("_update_censor_txn", _update_censor_txn)

    def _censor_event_txn(self, txn, event_id, pruned_json):
        """Censor an event by replacing its JSON in the event_json table with the
        provided pruned JSON.

        Args:
            txn (LoggingTransaction): The database transaction.
            event_id (str): The ID of the event to censor.
            pruned_json (str): The pruned JSON
        """
        self.db_pool.simple_update_one_txn(
            txn,
            table="event_json",
            keyvalues={"event_id": event_id},
            updatevalues={"json": pruned_json},
        )

        self.db_pool.simple_update_one_txn(
            txn,
            table="events",
            keyvalues={"event_id": event_id},
            updatevalues={"json": pruned_json},
        )

    async def expire_event(self, event_id: str) -> None:
        """Retrieve and expire an event that has expired, and delete its associated
        expiry timestamp. If the event can't be retrieved, delete its associated
        timestamp so we don't try to expire it again in the future.

        Args:
             event_id: The ID of the event to delete.
        """
        # Try to retrieve the event's content from the database or the event cache.
        event = await self.get_event(event_id)

        def delete_expired_event_txn(txn):
            # Delete the expiry timestamp associated with this event from the database.
            self._delete_event_expiry_txn(txn, event_id)

            if not event:
                # If we can't find the event, log a warning and delete the expiry date
                # from the database so that we don't try to expire it again in the
                # future.
                logger.warning(
                    "Can't expire event %s because we don't have it.", event_id
                )
                return

            # Prune the event's dict then convert it to JSON.
            pruned_json = json_encoder.encode(
                prune_event_dict(event.room_version, event.get_dict())
            )

            # Update the event_json table to replace the event's JSON with the pruned
            # JSON.
            self._censor_event_txn(txn, event.event_id, pruned_json)

            # We need to invalidate the event cache entry for this event because we
            # changed its content in the database. We can't call
            # self._invalidate_cache_and_stream because self.get_event_cache isn't of the
            # right type.
            txn.call_after(self._get_event_cache.invalidate, (event.event_id,))
            # Send that invalidation to replication so that other workers also invalidate
            # the event cache.
            self._send_invalidation_to_replication(
                txn, "_get_event_cache", (event.event_id,)
            )

        await self.db_pool.runInteraction(
            "delete_expired_event", delete_expired_event_txn
        )

    def _delete_event_expiry_txn(self, txn, event_id):
        """Delete the expiry timestamp associated with an event ID without deleting the
        actual event.

        Args:
            txn (LoggingTransaction): The transaction to use to perform the deletion.
            event_id (str): The event ID to delete the associated expiry timestamp of.
        """
        return self.db_pool.simple_delete_txn(
            txn=txn, table="event_expiry", keyvalues={"event_id": event_id}
        )
