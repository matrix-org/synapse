# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
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
import datetime
import logging
from typing import TYPE_CHECKING, Dict, Hashable, Iterable, List, Tuple

from prometheus_client import Counter

from synapse.api.errors import (
    FederationDeniedError,
    HttpResponseException,
    RequestSendFailed,
)
from synapse.events import EventBase
from synapse.federation.units import Edu
from synapse.handlers.presence import format_user_presence_state
from synapse.metrics import sent_transactions_counter
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.presence import UserPresenceState
from synapse.types import ReadReceipt
from synapse.util.retryutils import NotRetryingDestination, get_retry_limiter

if TYPE_CHECKING:
    import synapse.server

# This is defined in the Matrix spec and enforced by the receiver.
MAX_EDUS_PER_TRANSACTION = 100

logger = logging.getLogger(__name__)


sent_edus_counter = Counter(
    "synapse_federation_client_sent_edus", "Total number of EDUs successfully sent"
)

sent_edus_by_type = Counter(
    "synapse_federation_client_sent_edus_by_type",
    "Number of sent EDUs successfully sent, by event type",
    ["type"],
)


class PerDestinationQueue(object):
    """
    Manages the per-destination transmission queues.

    Args:
        hs
        transaction_sender
        destination: the server_name of the destination that we are managing
            transmission for.
    """

    def __init__(
        self,
        hs: "synapse.server.HomeServer",
        transaction_manager: "synapse.federation.sender.TransactionManager",
        destination: str,
    ):
        self._server_name = hs.hostname
        self._clock = hs.get_clock()
        self._store = hs.get_datastore()
        self._transaction_manager = transaction_manager

        self._destination = destination
        self.transmission_loop_running = False

        # a list of tuples of (pending pdu, order)
        self._pending_pdus = []  # type: List[Tuple[EventBase, int]]

        # XXX this is never actually used: see
        # https://github.com/matrix-org/synapse/issues/7549
        self._pending_edus = []  # type: List[Edu]

        # Pending EDUs by their "key". Keyed EDUs are EDUs that get clobbered
        # based on their key (e.g. typing events by room_id)
        # Map of (edu_type, key) -> Edu
        self._pending_edus_keyed = {}  # type: Dict[Tuple[str, Hashable], Edu]

        # Map of user_id -> UserPresenceState of pending presence to be sent to this
        # destination
        self._pending_presence = {}  # type: Dict[str, UserPresenceState]

        # room_id -> receipt_type -> user_id -> receipt_dict
        self._pending_rrs = {}  # type: Dict[str, Dict[str, Dict[str, dict]]]
        self._rrs_pending_flush = False

        # stream_id of last successfully sent to-device message.
        # NB: may be a long or an int.
        self._last_device_stream_id = 0

        # stream_id of last successfully sent device list update.
        self._last_device_list_stream_id = 0

    def __str__(self) -> str:
        return "PerDestinationQueue[%s]" % self._destination

    def pending_pdu_count(self) -> int:
        return len(self._pending_pdus)

    def pending_edu_count(self) -> int:
        return (
            len(self._pending_edus)
            + len(self._pending_presence)
            + len(self._pending_edus_keyed)
        )

    def send_pdu(self, pdu: EventBase, order: int) -> None:
        """Add a PDU to the queue, and start the transmission loop if neccessary

        Args:
            pdu: pdu to send
            order
        """
        self._pending_pdus.append((pdu, order))
        self.attempt_new_transaction()

    def send_presence(self, states: Iterable[UserPresenceState]) -> None:
        """Add presence updates to the queue. Start the transmission loop if neccessary.

        Args:
            states: presence to send
        """
        self._pending_presence.update({state.user_id: state for state in states})
        self.attempt_new_transaction()

    def queue_read_receipt(self, receipt: ReadReceipt) -> None:
        """Add a RR to the list to be sent. Doesn't start the transmission loop yet
        (see flush_read_receipts_for_room)

        Args:
            receipt: receipt to be queued
        """
        self._pending_rrs.setdefault(receipt.room_id, {}).setdefault(
            receipt.receipt_type, {}
        )[receipt.user_id] = {"event_ids": receipt.event_ids, "data": receipt.data}

    def flush_read_receipts_for_room(self, room_id: str) -> None:
        # if we don't have any read-receipts for this room, it may be that we've already
        # sent them out, so we don't need to flush.
        if room_id not in self._pending_rrs:
            return
        self._rrs_pending_flush = True
        self.attempt_new_transaction()

    def send_keyed_edu(self, edu: Edu, key: Hashable) -> None:
        self._pending_edus_keyed[(edu.edu_type, key)] = edu
        self.attempt_new_transaction()

    def send_edu(self, edu) -> None:
        self._pending_edus.append(edu)
        self.attempt_new_transaction()

    def attempt_new_transaction(self) -> None:
        """Try to start a new transaction to this destination

        If there is already a transaction in progress to this destination,
        returns immediately. Otherwise kicks off the process of sending a
        transaction in the background.
        """
        # list of (pending_pdu, deferred, order)
        if self.transmission_loop_running:
            # XXX: this can get stuck on by a never-ending
            # request at which point pending_pdus just keeps growing.
            # we need application-layer timeouts of some flavour of these
            # requests
            logger.debug("TX [%s] Transaction already in progress", self._destination)
            return

        logger.debug("TX [%s] Starting transaction loop", self._destination)

        run_as_background_process(
            "federation_transaction_transmission_loop",
            self._transaction_transmission_loop,
        )

    async def _transaction_transmission_loop(self) -> None:
        pending_pdus = []  # type: List[Tuple[EventBase, int]]
        try:
            self.transmission_loop_running = True

            # This will throw if we wouldn't retry. We do this here so we fail
            # quickly, but we will later check this again in the http client,
            # hence why we throw the result away.
            await get_retry_limiter(self._destination, self._clock, self._store)

            pending_pdus = []
            while True:
                # We have to keep 2 free slots for presence and rr_edus
                limit = MAX_EDUS_PER_TRANSACTION - 2

                device_update_edus, dev_list_id = await self._get_device_update_edus(
                    limit
                )

                limit -= len(device_update_edus)

                (
                    to_device_edus,
                    device_stream_id,
                ) = await self._get_to_device_message_edus(limit)

                pending_edus = device_update_edus + to_device_edus

                # BEGIN CRITICAL SECTION
                #
                # In order to avoid a race condition, we need to make sure that
                # the following code (from popping the queues up to the point
                # where we decide if we actually have any pending messages) is
                # atomic - otherwise new PDUs or EDUs might arrive in the
                # meantime, but not get sent because we hold the
                # transmission_loop_running flag.

                pending_pdus = self._pending_pdus

                # We can only include at most 50 PDUs per transactions
                pending_pdus, self._pending_pdus = pending_pdus[:50], pending_pdus[50:]

                pending_edus.extend(self._get_rr_edus(force_flush=False))
                pending_presence = self._pending_presence
                self._pending_presence = {}
                if pending_presence:
                    pending_edus.append(
                        Edu(
                            origin=self._server_name,
                            destination=self._destination,
                            edu_type="m.presence",
                            content={
                                "push": [
                                    format_user_presence_state(
                                        presence, self._clock.time_msec()
                                    )
                                    for presence in pending_presence.values()
                                ]
                            },
                        )
                    )

                pending_edus.extend(
                    self._pop_pending_edus(MAX_EDUS_PER_TRANSACTION - len(pending_edus))
                )
                while (
                    len(pending_edus) < MAX_EDUS_PER_TRANSACTION
                    and self._pending_edus_keyed
                ):
                    _, val = self._pending_edus_keyed.popitem()
                    pending_edus.append(val)

                if pending_pdus:
                    logger.debug(
                        "TX [%s] len(pending_pdus_by_dest[dest]) = %d",
                        self._destination,
                        len(pending_pdus),
                    )

                if not pending_pdus and not pending_edus:
                    logger.debug("TX [%s] Nothing to send", self._destination)
                    self._last_device_stream_id = device_stream_id
                    return

                # if we've decided to send a transaction anyway, and we have room, we
                # may as well send any pending RRs
                if len(pending_edus) < MAX_EDUS_PER_TRANSACTION:
                    pending_edus.extend(self._get_rr_edus(force_flush=True))

                # END CRITICAL SECTION

                success = await self._transaction_manager.send_new_transaction(
                    self._destination, pending_pdus, pending_edus
                )
                if success:
                    sent_transactions_counter.inc()
                    sent_edus_counter.inc(len(pending_edus))
                    for edu in pending_edus:
                        sent_edus_by_type.labels(edu.edu_type).inc()
                    # Remove the acknowledged device messages from the database
                    # Only bother if we actually sent some device messages
                    if to_device_edus:
                        await self._store.delete_device_msgs_for_remote(
                            self._destination, device_stream_id
                        )

                    # also mark the device updates as sent
                    if device_update_edus:
                        logger.info(
                            "Marking as sent %r %r", self._destination, dev_list_id
                        )
                        await self._store.mark_as_sent_devices_by_remote(
                            self._destination, dev_list_id
                        )

                    self._last_device_stream_id = device_stream_id
                    self._last_device_list_stream_id = dev_list_id
                else:
                    break
        except NotRetryingDestination as e:
            logger.debug(
                "TX [%s] not ready for retry yet (next retry at %s) - "
                "dropping transaction for now",
                self._destination,
                datetime.datetime.fromtimestamp(
                    (e.retry_last_ts + e.retry_interval) / 1000.0
                ),
            )
        except FederationDeniedError as e:
            logger.info(e)
        except HttpResponseException as e:
            logger.warning(
                "TX [%s] Received %d response to transaction: %s",
                self._destination,
                e.code,
                e,
            )
        except RequestSendFailed as e:
            logger.warning(
                "TX [%s] Failed to send transaction: %s", self._destination, e
            )

            for p, _ in pending_pdus:
                logger.info(
                    "Failed to send event %s to %s", p.event_id, self._destination
                )
        except Exception:
            logger.exception("TX [%s] Failed to send transaction", self._destination)
            for p, _ in pending_pdus:
                logger.info(
                    "Failed to send event %s to %s", p.event_id, self._destination
                )
        finally:
            # We want to be *very* sure we clear this after we stop processing
            self.transmission_loop_running = False

    def _get_rr_edus(self, force_flush: bool) -> Iterable[Edu]:
        if not self._pending_rrs:
            return
        if not force_flush and not self._rrs_pending_flush:
            # not yet time for this lot
            return

        edu = Edu(
            origin=self._server_name,
            destination=self._destination,
            edu_type="m.receipt",
            content=self._pending_rrs,
        )
        self._pending_rrs = {}
        self._rrs_pending_flush = False
        yield edu

    def _pop_pending_edus(self, limit: int) -> List[Edu]:
        pending_edus = self._pending_edus
        pending_edus, self._pending_edus = pending_edus[:limit], pending_edus[limit:]
        return pending_edus

    async def _get_device_update_edus(self, limit: int) -> Tuple[List[Edu], int]:
        last_device_list = self._last_device_list_stream_id

        # Retrieve list of new device updates to send to the destination
        now_stream_id, results = await self._store.get_device_updates_by_remote(
            self._destination, last_device_list, limit=limit
        )
        edus = [
            Edu(
                origin=self._server_name,
                destination=self._destination,
                edu_type=edu_type,
                content=content,
            )
            for (edu_type, content) in results
        ]

        assert len(edus) <= limit, "get_device_updates_by_remote returned too many EDUs"

        return (edus, now_stream_id)

    async def _get_to_device_message_edus(self, limit: int) -> Tuple[List[Edu], int]:
        last_device_stream_id = self._last_device_stream_id
        to_device_stream_id = self._store.get_to_device_stream_token()
        contents, stream_id = await self._store.get_new_device_msgs_for_remote(
            self._destination, last_device_stream_id, to_device_stream_id, limit
        )
        edus = [
            Edu(
                origin=self._server_name,
                destination=self._destination,
                edu_type="m.direct_to_device",
                content=content,
            )
            for content in contents
        ]

        return (edus, stream_id)
