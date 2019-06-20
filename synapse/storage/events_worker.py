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

from __future__ import division

import itertools
import logging
from collections import namedtuple

from canonicaljson import json

from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.api.errors import NotFoundError
from synapse.api.room_versions import EventFormatVersions
from synapse.events import FrozenEvent, event_type_from_format_version  # noqa: F401
from synapse.events.snapshot import EventContext  # noqa: F401
from synapse.events.utils import prune_event
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import get_domain_from_id
from synapse.util.logcontext import (
    LoggingContext,
    PreserveLoggingContext,
    make_deferred_yieldable,
    run_in_background,
)
from synapse.util.metrics import Measure

from ._base import SQLBaseStore

logger = logging.getLogger(__name__)


# These values are used in the `enqueus_event` and `_do_fetch` methods to
# control how we batch/bulk fetch events from the database.
# The values are plucked out of thing air to make initial sync run faster
# on jki.re
# TODO: Make these configurable.
EVENT_QUEUE_THREADS = 3  # Max number of threads that will fetch events
EVENT_QUEUE_ITERATIONS = 3  # No. times we block waiting for requests for events
EVENT_QUEUE_TIMEOUT_S = 0.1  # Timeout when waiting for requests for events


_EventCacheEntry = namedtuple("_EventCacheEntry", ("event", "redacted_event"))


class EventsWorkerStore(SQLBaseStore):
    def get_received_ts(self, event_id):
        """Get received_ts (when it was persisted) for the event.

        Raises an exception for unknown events.

        Args:
            event_id (str)

        Returns:
            Deferred[int|None]: Timestamp in milliseconds, or None for events
            that were persisted before received_ts was implemented.
        """
        return self._simple_select_one_onecol(
            table="events",
            keyvalues={"event_id": event_id},
            retcol="received_ts",
            desc="get_received_ts",
        )

    def get_received_ts_by_stream_pos(self, stream_ordering):
        """Given a stream ordering get an approximate timestamp of when it
        happened.

        This is done by simply taking the received ts of the first event that
        has a stream ordering greater than or equal to the given stream pos.
        If none exists returns the current time, on the assumption that it must
        have happened recently.

        Args:
            stream_ordering (int)

        Returns:
            Deferred[int]
        """

        def _get_approximate_received_ts_txn(txn):
            sql = """
                SELECT received_ts FROM events
                WHERE stream_ordering >= ?
                LIMIT 1
            """

            txn.execute(sql, (stream_ordering,))
            row = txn.fetchone()
            if row and row[0]:
                ts = row[0]
            else:
                ts = self.clock.time_msec()

            return ts

        return self.runInteraction(
            "get_approximate_received_ts", _get_approximate_received_ts_txn
        )

    @defer.inlineCallbacks
    def get_event(
        self,
        event_id,
        check_redacted=True,
        get_prev_content=False,
        allow_rejected=False,
        allow_none=False,
        check_room_id=None,
    ):
        """Get an event from the database by event_id.

        Args:
            event_id (str): The event_id of the event to fetch
            check_redacted (bool): If True, check if event has been redacted
                and redact it.
            get_prev_content (bool): If True and event is a state event,
                include the previous states content in the unsigned field.
            allow_rejected (bool): If True return rejected events.
            allow_none (bool): If True, return None if no event found, if
                False throw a NotFoundError
            check_room_id (str|None): if not None, check the room of the found event.
                If there is a mismatch, behave as per allow_none.

        Returns:
            Deferred : A FrozenEvent.
        """
        events = yield self.get_events_as_list(
            [event_id],
            check_redacted=check_redacted,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        event = events[0] if events else None

        if event is not None and check_room_id is not None:
            if event.room_id != check_room_id:
                event = None

        if event is None and not allow_none:
            raise NotFoundError("Could not find event %s" % (event_id,))

        defer.returnValue(event)

    @defer.inlineCallbacks
    def get_events(
        self,
        event_ids,
        check_redacted=True,
        get_prev_content=False,
        allow_rejected=False,
    ):
        """Get events from the database

        Args:
            event_ids (list): The event_ids of the events to fetch
            check_redacted (bool): If True, check if event has been redacted
                and redact it.
            get_prev_content (bool): If True and event is a state event,
                include the previous states content in the unsigned field.
            allow_rejected (bool): If True return rejected events.

        Returns:
            Deferred : Dict from event_id to event.
        """
        events = yield self.get_events_as_list(
            event_ids,
            check_redacted=check_redacted,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        defer.returnValue({e.event_id: e for e in events})

    @defer.inlineCallbacks
    def get_events_as_list(
        self,
        event_ids,
        check_redacted=True,
        get_prev_content=False,
        allow_rejected=False,
    ):
        """Get events from the database and return in a list in the same order
        as given by `event_ids` arg.

        Args:
            event_ids (list): The event_ids of the events to fetch
            check_redacted (bool): If True, check if event has been redacted
                and redact it.
            get_prev_content (bool): If True and event is a state event,
                include the previous states content in the unsigned field.
            allow_rejected (bool): If True return rejected events.

        Returns:
            Deferred[list[EventBase]]: List of events fetched from the database. The
            events are in the same order as `event_ids` arg.

            Note that the returned list may be smaller than the list of event
            IDs if not all events could be fetched.
        """

        if not event_ids:
            defer.returnValue([])

        event_id_list = event_ids
        event_ids = set(event_ids)

        event_entry_map = self._get_events_from_cache(
            event_ids, allow_rejected=allow_rejected
        )

        missing_events_ids = [e for e in event_ids if e not in event_entry_map]

        if missing_events_ids:
            log_ctx = LoggingContext.current_context()
            log_ctx.record_event_fetch(len(missing_events_ids))

            # Note that _enqueue_events is also responsible for turning db rows
            # into FrozenEvents (via _get_event_from_row), which involves seeing if
            # the events have been redacted, and if so pulling the redaction event out
            # of the database to check it.
            #
            # _enqueue_events is a bit of a rubbish name but naming is hard.
            missing_events = yield self._enqueue_events(
                missing_events_ids, allow_rejected=allow_rejected
            )

            event_entry_map.update(missing_events)

        events = []
        for event_id in event_id_list:
            entry = event_entry_map.get(event_id, None)
            if not entry:
                continue

            # Starting in room version v3, some redactions need to be rechecked if we
            # didn't have the redacted event at the time, so we recheck on read
            # instead.
            if not allow_rejected and entry.event.type == EventTypes.Redaction:
                if entry.event.internal_metadata.need_to_check_redaction():
                    # XXX: we need to avoid calling get_event here.
                    #
                    # The problem is that we end up at this point when an event
                    # which has been redacted is pulled out of the database by
                    # _enqueue_events, because _enqueue_events needs to check
                    # the redaction before it can cache the redacted event. So
                    # obviously, calling get_event to get the redacted event out
                    # of the database gives us an infinite loop.
                    #
                    # For now (quick hack to fix during 0.99 release cycle), we
                    # just go and fetch the relevant row from the db, but it
                    # would be nice to think about how we can cache this rather
                    # than hit the db every time we access a redaction event.
                    #
                    # One thought on how to do this:
                    #  1. split get_events_as_list up so that it is divided into
                    #     (a) get the rawish event from the db/cache, (b) do the
                    #     redaction/rejection filtering
                    #  2. have _get_event_from_row just call the first half of
                    #     that

                    orig_sender = yield self._simple_select_one_onecol(
                        table="events",
                        keyvalues={"event_id": entry.event.redacts},
                        retcol="sender",
                        allow_none=True,
                    )

                    expected_domain = get_domain_from_id(entry.event.sender)
                    if (
                        orig_sender
                        and get_domain_from_id(orig_sender) == expected_domain
                    ):
                        # This redaction event is allowed. Mark as not needing a
                        # recheck.
                        entry.event.internal_metadata.recheck_redaction = False
                    else:
                        # We don't have the event that is being redacted, so we
                        # assume that the event isn't authorized for now. (If we
                        # later receive the event, then we will always redact
                        # it anyway, since we have this redaction)
                        continue

            if allow_rejected or not entry.event.rejected_reason:
                if check_redacted and entry.redacted_event:
                    event = entry.redacted_event
                else:
                    event = entry.event

                events.append(event)

                if get_prev_content:
                    if "replaces_state" in event.unsigned:
                        prev = yield self.get_event(
                            event.unsigned["replaces_state"],
                            get_prev_content=False,
                            allow_none=True,
                        )
                        if prev:
                            event.unsigned = dict(event.unsigned)
                            event.unsigned["prev_content"] = prev.content
                            event.unsigned["prev_sender"] = prev.sender

        defer.returnValue(events)

    def _invalidate_get_event_cache(self, event_id):
        self._get_event_cache.invalidate((event_id,))

    def _get_events_from_cache(self, events, allow_rejected, update_metrics=True):
        """Fetch events from the caches

        Args:
            events (list(str)): list of event_ids to fetch
            allow_rejected (bool): Whether to teturn events that were rejected
            update_metrics (bool): Whether to update the cache hit ratio metrics

        Returns:
            dict of event_id -> _EventCacheEntry for each event_id in cache. If
            allow_rejected is `False` then there will still be an entry but it
            will be `None`
        """
        event_map = {}

        for event_id in events:
            ret = self._get_event_cache.get(
                (event_id,), None, update_metrics=update_metrics
            )
            if not ret:
                continue

            if allow_rejected or not ret.event.rejected_reason:
                event_map[event_id] = ret
            else:
                event_map[event_id] = None

        return event_map

    def _do_fetch(self, conn):
        """Takes a database connection and waits for requests for events from
        the _event_fetch_list queue.
        """
        i = 0
        while True:
            with self._event_fetch_lock:
                event_list = self._event_fetch_list
                self._event_fetch_list = []

                if not event_list:
                    single_threaded = self.database_engine.single_threaded
                    if single_threaded or i > EVENT_QUEUE_ITERATIONS:
                        self._event_fetch_ongoing -= 1
                        return
                    else:
                        self._event_fetch_lock.wait(EVENT_QUEUE_TIMEOUT_S)
                        i += 1
                        continue
                i = 0

            self._fetch_event_list(conn, event_list)

    def _fetch_event_list(self, conn, event_list):
        """Handle a load of requests from the _event_fetch_list queue

        Args:
            conn (twisted.enterprise.adbapi.Connection): database connection

            event_list (list[Tuple[list[str], Deferred]]):
                The fetch requests. Each entry consists of a list of event
                ids to be fetched, and a deferred to be completed once the
                events have been fetched.

        """
        with Measure(self._clock, "_fetch_event_list"):
            try:
                event_id_lists = list(zip(*event_list))[0]
                event_ids = [item for sublist in event_id_lists for item in sublist]

                rows = self._new_transaction(
                    conn, "do_fetch", [], [], self._fetch_event_rows, event_ids
                )

                row_dict = {r["event_id"]: r for r in rows}

                # We only want to resolve deferreds from the main thread
                def fire(lst, res):
                    for ids, d in lst:
                        if not d.called:
                            try:
                                with PreserveLoggingContext():
                                    d.callback([res[i] for i in ids if i in res])
                            except Exception:
                                logger.exception("Failed to callback")

                with PreserveLoggingContext():
                    self.hs.get_reactor().callFromThread(fire, event_list, row_dict)
            except Exception as e:
                logger.exception("do_fetch")

                # We only want to resolve deferreds from the main thread
                def fire(evs, exc):
                    for _, d in evs:
                        if not d.called:
                            with PreserveLoggingContext():
                                d.errback(exc)

                with PreserveLoggingContext():
                    self.hs.get_reactor().callFromThread(fire, event_list, e)

    @defer.inlineCallbacks
    def _enqueue_events(self, events, allow_rejected=False):
        """Fetches events from the database using the _event_fetch_list. This
        allows batch and bulk fetching of events - it allows us to fetch events
        without having to create a new transaction for each request for events.
        """
        if not events:
            defer.returnValue({})

        events_d = defer.Deferred()
        with self._event_fetch_lock:
            self._event_fetch_list.append((events, events_d))

            self._event_fetch_lock.notify()

            if self._event_fetch_ongoing < EVENT_QUEUE_THREADS:
                self._event_fetch_ongoing += 1
                should_start = True
            else:
                should_start = False

        if should_start:
            run_as_background_process(
                "fetch_events", self.runWithConnection, self._do_fetch
            )

        logger.debug("Loading %d events", len(events))
        with PreserveLoggingContext():
            rows = yield events_d
        logger.debug("Loaded %d events (%d rows)", len(events), len(rows))

        if not allow_rejected:
            rows[:] = [r for r in rows if not r["rejects"]]

        res = yield make_deferred_yieldable(
            defer.gatherResults(
                [
                    run_in_background(
                        self._get_event_from_row,
                        row["internal_metadata"],
                        row["json"],
                        row["redacts"],
                        rejected_reason=row["rejects"],
                        format_version=row["format_version"],
                    )
                    for row in rows
                ],
                consumeErrors=True,
            )
        )

        defer.returnValue({e.event.event_id: e for e in res if e})

    def _fetch_event_rows(self, txn, events):
        rows = []
        N = 200
        for i in range(1 + len(events) // N):
            evs = events[i * N : (i + 1) * N]
            if not evs:
                break

            sql = (
                "SELECT "
                " e.event_id as event_id, "
                " e.internal_metadata,"
                " e.json,"
                " e.format_version, "
                " r.redacts as redacts,"
                " rej.event_id as rejects "
                " FROM event_json as e"
                " LEFT JOIN rejections as rej USING (event_id)"
                " LEFT JOIN redactions as r ON e.event_id = r.redacts"
                " WHERE e.event_id IN (%s)"
            ) % (",".join(["?"] * len(evs)),)

            txn.execute(sql, evs)
            rows.extend(self.cursor_to_dict(txn))

        return rows

    @defer.inlineCallbacks
    def _get_event_from_row(
        self, internal_metadata, js, redacted, format_version, rejected_reason=None
    ):
        with Measure(self._clock, "_get_event_from_row"):
            d = json.loads(js)
            internal_metadata = json.loads(internal_metadata)

            if rejected_reason:
                rejected_reason = yield self._simple_select_one_onecol(
                    table="rejections",
                    keyvalues={"event_id": rejected_reason},
                    retcol="reason",
                    desc="_get_event_from_row_rejected_reason",
                )

            if format_version is None:
                # This means that we stored the event before we had the concept
                # of a event format version, so it must be a V1 event.
                format_version = EventFormatVersions.V1

            original_ev = event_type_from_format_version(format_version)(
                event_dict=d,
                internal_metadata_dict=internal_metadata,
                rejected_reason=rejected_reason,
            )

            redacted_event = None
            if redacted:
                redacted_event = prune_event(original_ev)

                redaction_id = yield self._simple_select_one_onecol(
                    table="redactions",
                    keyvalues={"redacts": redacted_event.event_id},
                    retcol="event_id",
                    desc="_get_event_from_row_redactions",
                )

                redacted_event.unsigned["redacted_by"] = redaction_id
                # Get the redaction event.

                because = yield self.get_event(
                    redaction_id, check_redacted=False, allow_none=True
                )

                if because:
                    # It's fine to do add the event directly, since get_pdu_json
                    # will serialise this field correctly
                    redacted_event.unsigned["redacted_because"] = because

                    # Starting in room version v3, some redactions need to be
                    # rechecked if we didn't have the redacted event at the
                    # time, so we recheck on read instead.
                    if because.internal_metadata.need_to_check_redaction():
                        expected_domain = get_domain_from_id(original_ev.sender)
                        if get_domain_from_id(because.sender) == expected_domain:
                            # This redaction event is allowed. Mark as not needing a
                            # recheck.
                            because.internal_metadata.recheck_redaction = False
                        else:
                            # Senders don't match, so the event isn't actually redacted
                            redacted_event = None

            cache_entry = _EventCacheEntry(
                event=original_ev, redacted_event=redacted_event
            )

            self._get_event_cache.prefill((original_ev.event_id,), cache_entry)

        defer.returnValue(cache_entry)

    @defer.inlineCallbacks
    def have_events_in_timeline(self, event_ids):
        """Given a list of event ids, check if we have already processed and
        stored them as non outliers.
        """
        rows = yield self._simple_select_many_batch(
            table="events",
            retcols=("event_id",),
            column="event_id",
            iterable=list(event_ids),
            keyvalues={"outlier": False},
            desc="have_events_in_timeline",
        )

        defer.returnValue(set(r["event_id"] for r in rows))

    @defer.inlineCallbacks
    def have_seen_events(self, event_ids):
        """Given a list of event ids, check if we have already processed them.

        Args:
            event_ids (iterable[str]):

        Returns:
            Deferred[set[str]]: The events we have already seen.
        """
        results = set()

        def have_seen_events_txn(txn, chunk):
            sql = "SELECT event_id FROM events as e WHERE e.event_id IN (%s)" % (
                ",".join("?" * len(chunk)),
            )
            txn.execute(sql, chunk)
            for (event_id,) in txn:
                results.add(event_id)

        # break the input up into chunks of 100
        input_iterator = iter(event_ids)
        for chunk in iter(lambda: list(itertools.islice(input_iterator, 100)), []):
            yield self.runInteraction("have_seen_events", have_seen_events_txn, chunk)
        defer.returnValue(results)

    def get_seen_events_with_rejections(self, event_ids):
        """Given a list of event ids, check if we rejected them.

        Args:
            event_ids (list[str])

        Returns:
            Deferred[dict[str, str|None):
                Has an entry for each event id we already have seen. Maps to
                the rejected reason string if we rejected the event, else maps
                to None.
        """
        if not event_ids:
            return defer.succeed({})

        def f(txn):
            sql = (
                "SELECT e.event_id, reason FROM events as e "
                "LEFT JOIN rejections as r ON e.event_id = r.event_id "
                "WHERE e.event_id = ?"
            )

            res = {}
            for event_id in event_ids:
                txn.execute(sql, (event_id,))
                row = txn.fetchone()
                if row:
                    _, rejected = row
                    res[event_id] = rejected

            return res

        return self.runInteraction("get_seen_events_with_rejections", f)

    def _get_total_state_event_counts_txn(self, txn, room_id):
        """
        See get_total_state_event_counts.
        """
        # We join against the events table as that has an index on room_id
        sql = """
            SELECT COUNT(*) FROM state_events
            INNER JOIN events USING (room_id, event_id)
            WHERE room_id=?
        """
        txn.execute(sql, (room_id,))
        row = txn.fetchone()
        return row[0] if row else 0

    def get_total_state_event_counts(self, room_id):
        """
        Gets the total number of state events in a room.

        Args:
            room_id (str)

        Returns:
            Deferred[int]
        """
        return self.runInteraction(
            "get_total_state_event_counts",
            self._get_total_state_event_counts_txn,
            room_id,
        )

    def _get_current_state_event_counts_txn(self, txn, room_id):
        """
        See get_current_state_event_counts.
        """
        sql = "SELECT COUNT(*) FROM current_state_events WHERE room_id=?"
        txn.execute(sql, (room_id,))
        row = txn.fetchone()
        return row[0] if row else 0

    def get_current_state_event_counts(self, room_id):
        """
        Gets the current number of state events in a room.

        Args:
            room_id (str)

        Returns:
            Deferred[int]
        """
        return self.runInteraction(
            "get_current_state_event_counts",
            self._get_current_state_event_counts_txn,
            room_id,
        )

    @defer.inlineCallbacks
    def get_room_complexity(self, room_id):
        """
        Get a rough approximation of the complexity of the room. This is used by
        remote servers to decide whether they wish to join the room or not.
        Higher complexity value indicates that being in the room will consume
        more resources.

        Args:
            room_id (str)

        Returns:
            Deferred[dict[str:int]] of complexity version to complexity.
        """
        state_events = yield self.get_current_state_event_counts(room_id)

        # Call this one "v1", so we can introduce new ones as we want to develop
        # it.
        complexity_v1 = round(state_events / 500, 2)

        defer.returnValue({"v1": complexity_v1})
