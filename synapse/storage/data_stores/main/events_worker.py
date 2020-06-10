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
import threading
from collections import namedtuple
from typing import List, Optional, Tuple

from canonicaljson import json
from constantly import NamedConstant, Names

from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.api.errors import NotFoundError, SynapseError
from synapse.api.room_versions import (
    KNOWN_ROOM_VERSIONS,
    EventFormatVersions,
    RoomVersions,
)
from synapse.events import make_event_from_dict
from synapse.events.utils import prune_event
from synapse.logging.context import PreserveLoggingContext, current_context
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.slave.storage._slaved_id_tracker import SlavedIdTracker
from synapse.storage._base import SQLBaseStore, make_in_list_sql_clause
from synapse.storage.database import Database
from synapse.storage.util.id_generators import StreamIdGenerator
from synapse.types import get_domain_from_id
from synapse.util.caches.descriptors import Cache, cached, cachedInlineCallbacks
from synapse.util.iterutils import batch_iter
from synapse.util.metrics import Measure

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


class EventRedactBehaviour(Names):
    """
    What to do when retrieving a redacted event from the database.
    """

    AS_IS = NamedConstant()
    REDACT = NamedConstant()
    BLOCK = NamedConstant()


class EventsWorkerStore(SQLBaseStore):
    def __init__(self, database: Database, db_conn, hs):
        super(EventsWorkerStore, self).__init__(database, db_conn, hs)

        if hs.config.worker.writers.events == hs.get_instance_name():
            # We are the process in charge of generating stream ids for events,
            # so instantiate ID generators based on the database
            self._stream_id_gen = StreamIdGenerator(
                db_conn,
                "events",
                "stream_ordering",
                extra_tables=[("local_invites", "stream_id")],
            )
            self._backfill_id_gen = StreamIdGenerator(
                db_conn,
                "events",
                "stream_ordering",
                step=-1,
                extra_tables=[("ex_outlier_stream", "event_stream_ordering")],
            )
        else:
            # Another process is in charge of persisting events and generating
            # stream IDs: rely on the replication streams to let us know which
            # IDs we can process.
            self._stream_id_gen = SlavedIdTracker(db_conn, "events", "stream_ordering")
            self._backfill_id_gen = SlavedIdTracker(
                db_conn, "events", "stream_ordering", step=-1
            )

        self._get_event_cache = Cache(
            "*getEvent*",
            keylen=3,
            max_entries=hs.config.caches.event_cache_size,
            apply_cache_factor_from_config=False,
        )

        self._event_fetch_lock = threading.Condition()
        self._event_fetch_list = []
        self._event_fetch_ongoing = 0

    def process_replication_rows(self, stream_name, instance_name, token, rows):
        if stream_name == "events":
            self._stream_id_gen.advance(token)
        elif stream_name == "backfill":
            self._backfill_id_gen.advance(-token)

        super().process_replication_rows(stream_name, instance_name, token, rows)

    def get_received_ts(self, event_id):
        """Get received_ts (when it was persisted) for the event.

        Raises an exception for unknown events.

        Args:
            event_id (str)

        Returns:
            Deferred[int|None]: Timestamp in milliseconds, or None for events
            that were persisted before received_ts was implemented.
        """
        return self.db.simple_select_one_onecol(
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

        return self.db.runInteraction(
            "get_approximate_received_ts", _get_approximate_received_ts_txn
        )

    @defer.inlineCallbacks
    def get_event(
        self,
        event_id: str,
        redact_behaviour: EventRedactBehaviour = EventRedactBehaviour.REDACT,
        get_prev_content: bool = False,
        allow_rejected: bool = False,
        allow_none: bool = False,
        check_room_id: Optional[str] = None,
    ):
        """Get an event from the database by event_id.

        Args:
            event_id: The event_id of the event to fetch

            redact_behaviour: Determine what to do with a redacted event. Possible values:
                * AS_IS - Return the full event body with no redacted content
                * REDACT - Return the event but with a redacted body
                * DISALLOW - Do not return redacted events (behave as per allow_none
                    if the event is redacted)

            get_prev_content: If True and event is a state event,
                include the previous states content in the unsigned field.

            allow_rejected: If True, return rejected events. Otherwise,
                behave as per allow_none.

            allow_none: If True, return None if no event found, if
                False throw a NotFoundError

            check_room_id: if not None, check the room of the found event.
                If there is a mismatch, behave as per allow_none.

        Returns:
            Deferred[EventBase|None]
        """
        if not isinstance(event_id, str):
            raise TypeError("Invalid event event_id %r" % (event_id,))

        events = yield self.get_events_as_list(
            [event_id],
            redact_behaviour=redact_behaviour,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        event = events[0] if events else None

        if event is not None and check_room_id is not None:
            if event.room_id != check_room_id:
                event = None

        if event is None and not allow_none:
            raise NotFoundError("Could not find event %s" % (event_id,))

        return event

    @defer.inlineCallbacks
    def get_events(
        self,
        event_ids: List[str],
        redact_behaviour: EventRedactBehaviour = EventRedactBehaviour.REDACT,
        get_prev_content: bool = False,
        allow_rejected: bool = False,
    ):
        """Get events from the database

        Args:
            event_ids: The event_ids of the events to fetch

            redact_behaviour: Determine what to do with a redacted event. Possible
                values:
                * AS_IS - Return the full event body with no redacted content
                * REDACT - Return the event but with a redacted body
                * DISALLOW - Do not return redacted events (omit them from the response)

            get_prev_content: If True and event is a state event,
                include the previous states content in the unsigned field.

            allow_rejected: If True, return rejected events. Otherwise,
                omits rejeted events from the response.

        Returns:
            Deferred : Dict from event_id to event.
        """
        events = yield self.get_events_as_list(
            event_ids,
            redact_behaviour=redact_behaviour,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        return {e.event_id: e for e in events}

    @defer.inlineCallbacks
    def get_events_as_list(
        self,
        event_ids: List[str],
        redact_behaviour: EventRedactBehaviour = EventRedactBehaviour.REDACT,
        get_prev_content: bool = False,
        allow_rejected: bool = False,
    ):
        """Get events from the database and return in a list in the same order
        as given by `event_ids` arg.

        Unknown events will be omitted from the response.

        Args:
            event_ids: The event_ids of the events to fetch

            redact_behaviour: Determine what to do with a redacted event. Possible values:
                * AS_IS - Return the full event body with no redacted content
                * REDACT - Return the event but with a redacted body
                * DISALLOW - Do not return redacted events (omit them from the response)

            get_prev_content: If True and event is a state event,
                include the previous states content in the unsigned field.

            allow_rejected: If True, return rejected events. Otherwise,
                omits rejected events from the response.

        Returns:
            Deferred[list[EventBase]]: List of events fetched from the database. The
            events are in the same order as `event_ids` arg.

            Note that the returned list may be smaller than the list of event
            IDs if not all events could be fetched.
        """

        if not event_ids:
            return []

        # there may be duplicates so we cast the list to a set
        event_entry_map = yield self._get_events_from_cache_or_db(
            set(event_ids), allow_rejected=allow_rejected
        )

        events = []
        for event_id in event_ids:
            entry = event_entry_map.get(event_id, None)
            if not entry:
                continue

            if not allow_rejected:
                assert not entry.event.rejected_reason, (
                    "rejected event returned from _get_events_from_cache_or_db despite "
                    "allow_rejected=False"
                )

            # We may not have had the original event when we received a redaction, so
            # we have to recheck auth now.

            if not allow_rejected and entry.event.type == EventTypes.Redaction:
                if entry.event.redacts is None:
                    # A redacted redaction doesn't have a `redacts` key, in
                    # which case lets just withhold the event.
                    #
                    # Note: Most of the time if the redactions has been
                    # redacted we still have the un-redacted event in the DB
                    # and so we'll still see the `redacts` key. However, this
                    # isn't always true e.g. if we have censored the event.
                    logger.debug(
                        "Withholding redaction event %s as we don't have redacts key",
                        event_id,
                    )
                    continue

                redacted_event_id = entry.event.redacts
                event_map = yield self._get_events_from_cache_or_db([redacted_event_id])
                original_event_entry = event_map.get(redacted_event_id)
                if not original_event_entry:
                    # we don't have the redacted event (or it was rejected).
                    #
                    # We assume that the redaction isn't authorized for now; if the
                    # redacted event later turns up, the redaction will be re-checked,
                    # and if it is found valid, the original will get redacted before it
                    # is served to the client.
                    logger.debug(
                        "Withholding redaction event %s since we don't (yet) have the "
                        "original %s",
                        event_id,
                        redacted_event_id,
                    )
                    continue

                original_event = original_event_entry.event
                if original_event.type == EventTypes.Create:
                    # we never serve redactions of Creates to clients.
                    logger.info(
                        "Withholding redaction %s of create event %s",
                        event_id,
                        redacted_event_id,
                    )
                    continue

                if original_event.room_id != entry.event.room_id:
                    logger.info(
                        "Withholding redaction %s of event %s from a different room",
                        event_id,
                        redacted_event_id,
                    )
                    continue

                if entry.event.internal_metadata.need_to_check_redaction():
                    original_domain = get_domain_from_id(original_event.sender)
                    redaction_domain = get_domain_from_id(entry.event.sender)
                    if original_domain != redaction_domain:
                        # the senders don't match, so this is forbidden
                        logger.info(
                            "Withholding redaction %s whose sender domain %s doesn't "
                            "match that of redacted event %s %s",
                            event_id,
                            redaction_domain,
                            redacted_event_id,
                            original_domain,
                        )
                        continue

                    # Update the cache to save doing the checks again.
                    entry.event.internal_metadata.recheck_redaction = False

            event = entry.event

            if entry.redacted_event:
                if redact_behaviour == EventRedactBehaviour.BLOCK:
                    # Skip this event
                    continue
                elif redact_behaviour == EventRedactBehaviour.REDACT:
                    event = entry.redacted_event

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

        return events

    @defer.inlineCallbacks
    def _get_events_from_cache_or_db(self, event_ids, allow_rejected=False):
        """Fetch a bunch of events from the cache or the database.

        If events are pulled from the database, they will be cached for future lookups.

        Unknown events are omitted from the response.

        Args:

            event_ids (Iterable[str]): The event_ids of the events to fetch

            allow_rejected (bool): Whether to include rejected events. If False,
                rejected events are omitted from the response.

        Returns:
            Deferred[Dict[str, _EventCacheEntry]]:
                map from event id to result
        """
        event_entry_map = self._get_events_from_cache(
            event_ids, allow_rejected=allow_rejected
        )

        missing_events_ids = [e for e in event_ids if e not in event_entry_map]

        if missing_events_ids:
            log_ctx = current_context()
            log_ctx.record_event_fetch(len(missing_events_ids))

            # Note that _get_events_from_db is also responsible for turning db rows
            # into FrozenEvents (via _get_event_from_row), which involves seeing if
            # the events have been redacted, and if so pulling the redaction event out
            # of the database to check it.
            #
            missing_events = yield self._get_events_from_db(
                missing_events_ids, allow_rejected=allow_rejected
            )

            event_entry_map.update(missing_events)

        return event_entry_map

    def _invalidate_get_event_cache(self, event_id):
        self._get_event_cache.invalidate((event_id,))

    def _get_events_from_cache(self, events, allow_rejected, update_metrics=True):
        """Fetch events from the caches

        Args:
            events (Iterable[str]): list of event_ids to fetch
            allow_rejected (bool): Whether to return events that were rejected
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

                The deferreds are callbacked with a dictionary mapping from event id
                to event row. Note that it may well contain additional events that
                were not part of this request.
        """
        with Measure(self._clock, "_fetch_event_list"):
            try:
                events_to_fetch = {
                    event_id for events, _ in event_list for event_id in events
                }

                row_dict = self.db.new_transaction(
                    conn, "do_fetch", [], [], self._fetch_event_rows, events_to_fetch
                )

                # We only want to resolve deferreds from the main thread
                def fire():
                    for _, d in event_list:
                        d.callback(row_dict)

                with PreserveLoggingContext():
                    self.hs.get_reactor().callFromThread(fire)
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
    def _get_events_from_db(self, event_ids, allow_rejected=False):
        """Fetch a bunch of events from the database.

        Returned events will be added to the cache for future lookups.

        Unknown events are omitted from the response.

        Args:
            event_ids (Iterable[str]): The event_ids of the events to fetch

            allow_rejected (bool): Whether to include rejected events. If False,
                rejected events are omitted from the response.

        Returns:
            Deferred[Dict[str, _EventCacheEntry]]:
                map from event id to result. May return extra events which
                weren't asked for.
        """
        fetched_events = {}
        events_to_fetch = event_ids

        while events_to_fetch:
            row_map = yield self._enqueue_events(events_to_fetch)

            # we need to recursively fetch any redactions of those events
            redaction_ids = set()
            for event_id in events_to_fetch:
                row = row_map.get(event_id)
                fetched_events[event_id] = row
                if row:
                    redaction_ids.update(row["redactions"])

            events_to_fetch = redaction_ids.difference(fetched_events.keys())
            if events_to_fetch:
                logger.debug("Also fetching redaction events %s", events_to_fetch)

        # build a map from event_id to EventBase
        event_map = {}
        for event_id, row in fetched_events.items():
            if not row:
                continue
            assert row["event_id"] == event_id

            rejected_reason = row["rejected_reason"]

            if not allow_rejected and rejected_reason:
                continue

            d = json.loads(row["json"])
            internal_metadata = json.loads(row["internal_metadata"])

            format_version = row["format_version"]
            if format_version is None:
                # This means that we stored the event before we had the concept
                # of a event format version, so it must be a V1 event.
                format_version = EventFormatVersions.V1

            room_version_id = row["room_version_id"]

            if not room_version_id:
                # this should only happen for out-of-band membership events
                if not internal_metadata.get("out_of_band_membership"):
                    logger.warning(
                        "Room %s for event %s is unknown", d["room_id"], event_id
                    )
                    continue

                # take a wild stab at the room version based on the event format
                if format_version == EventFormatVersions.V1:
                    room_version = RoomVersions.V1
                elif format_version == EventFormatVersions.V2:
                    room_version = RoomVersions.V3
                else:
                    room_version = RoomVersions.V5
            else:
                room_version = KNOWN_ROOM_VERSIONS.get(room_version_id)
                if not room_version:
                    logger.error(
                        "Event %s in room %s has unknown room version %s",
                        event_id,
                        d["room_id"],
                        room_version_id,
                    )
                    continue

                if room_version.event_format != format_version:
                    logger.error(
                        "Event %s in room %s with version %s has wrong format: "
                        "expected %s, was %s",
                        event_id,
                        d["room_id"],
                        room_version_id,
                        room_version.event_format,
                        format_version,
                    )
                    continue

            original_ev = make_event_from_dict(
                event_dict=d,
                room_version=room_version,
                internal_metadata_dict=internal_metadata,
                rejected_reason=rejected_reason,
            )

            event_map[event_id] = original_ev

        # finally, we can decide whether each one needs redacting, and build
        # the cache entries.
        result_map = {}
        for event_id, original_ev in event_map.items():
            redactions = fetched_events[event_id]["redactions"]
            redacted_event = self._maybe_redact_event_row(
                original_ev, redactions, event_map
            )

            cache_entry = _EventCacheEntry(
                event=original_ev, redacted_event=redacted_event
            )

            self._get_event_cache.prefill((event_id,), cache_entry)
            result_map[event_id] = cache_entry

        return result_map

    @defer.inlineCallbacks
    def _enqueue_events(self, events):
        """Fetches events from the database using the _event_fetch_list. This
        allows batch and bulk fetching of events - it allows us to fetch events
        without having to create a new transaction for each request for events.

        Args:
            events (Iterable[str]): events to be fetched.

        Returns:
            Deferred[Dict[str, Dict]]: map from event id to row data from the database.
                May contain events that weren't requested.
        """

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
                "fetch_events", self.db.runWithConnection, self._do_fetch
            )

        logger.debug("Loading %d events: %s", len(events), events)
        with PreserveLoggingContext():
            row_map = yield events_d
        logger.debug("Loaded %d events (%d rows)", len(events), len(row_map))

        return row_map

    def _fetch_event_rows(self, txn, event_ids):
        """Fetch event rows from the database

        Events which are not found are omitted from the result.

        The returned per-event dicts contain the following keys:

         * event_id (str)

         * json (str): json-encoded event structure

         * internal_metadata (str): json-encoded internal metadata dict

         * format_version (int|None): The format of the event. Hopefully one
           of EventFormatVersions. 'None' means the event predates
           EventFormatVersions (so the event is format V1).

         * room_version_id (str|None): The version of the room which contains the event.
           Hopefully one of RoomVersions.

           Due to historical reasons, there may be a few events in the database which
           do not have an associated room; in this case None will be returned here.

         * rejected_reason (str|None): if the event was rejected, the reason
           why.

         * redactions (List[str]): a list of event-ids which (claim to) redact
           this event.

        Args:
            txn (twisted.enterprise.adbapi.Connection):
            event_ids (Iterable[str]): event IDs to fetch

        Returns:
            Dict[str, Dict]: a map from event id to event info.
        """
        event_dict = {}
        for evs in batch_iter(event_ids, 200):
            sql = """\
                SELECT
                  e.event_id,
                  e.internal_metadata,
                  e.json,
                  e.format_version,
                  r.room_version,
                  rej.reason
                FROM event_json as e
                  LEFT JOIN rooms r USING (room_id)
                  LEFT JOIN rejections as rej USING (event_id)
                WHERE """

            clause, args = make_in_list_sql_clause(
                txn.database_engine, "e.event_id", evs
            )

            txn.execute(sql + clause, args)

            for row in txn:
                event_id = row[0]
                event_dict[event_id] = {
                    "event_id": event_id,
                    "internal_metadata": row[1],
                    "json": row[2],
                    "format_version": row[3],
                    "room_version_id": row[4],
                    "rejected_reason": row[5],
                    "redactions": [],
                }

            # check for redactions
            redactions_sql = "SELECT event_id, redacts FROM redactions WHERE "

            clause, args = make_in_list_sql_clause(txn.database_engine, "redacts", evs)

            txn.execute(redactions_sql + clause, args)

            for (redacter, redacted) in txn:
                d = event_dict.get(redacted)
                if d:
                    d["redactions"].append(redacter)

        return event_dict

    def _maybe_redact_event_row(self, original_ev, redactions, event_map):
        """Given an event object and a list of possible redacting event ids,
        determine whether to honour any of those redactions and if so return a redacted
        event.

        Args:
             original_ev (EventBase):
             redactions (iterable[str]): list of event ids of potential redaction events
             event_map (dict[str, EventBase]): other events which have been fetched, in
                 which we can look up the redaaction events. Map from event id to event.

        Returns:
            Deferred[EventBase|None]: if the event should be redacted, a pruned
                event object. Otherwise, None.
        """
        if original_ev.type == "m.room.create":
            # we choose to ignore redactions of m.room.create events.
            return None

        for redaction_id in redactions:
            redaction_event = event_map.get(redaction_id)
            if not redaction_event or redaction_event.rejected_reason:
                # we don't have the redaction event, or the redaction event was not
                # authorized.
                logger.debug(
                    "%s was redacted by %s but redaction not found/authed",
                    original_ev.event_id,
                    redaction_id,
                )
                continue

            if redaction_event.room_id != original_ev.room_id:
                logger.debug(
                    "%s was redacted by %s but redaction was in a different room!",
                    original_ev.event_id,
                    redaction_id,
                )
                continue

            # Starting in room version v3, some redactions need to be
            # rechecked if we didn't have the redacted event at the
            # time, so we recheck on read instead.
            if redaction_event.internal_metadata.need_to_check_redaction():
                expected_domain = get_domain_from_id(original_ev.sender)
                if get_domain_from_id(redaction_event.sender) == expected_domain:
                    # This redaction event is allowed. Mark as not needing a recheck.
                    redaction_event.internal_metadata.recheck_redaction = False
                else:
                    # Senders don't match, so the event isn't actually redacted
                    logger.debug(
                        "%s was redacted by %s but the senders don't match",
                        original_ev.event_id,
                        redaction_id,
                    )
                    continue

            logger.debug("Redacting %s due to %s", original_ev.event_id, redaction_id)

            # we found a good redaction event. Redact!
            redacted_event = prune_event(original_ev)
            redacted_event.unsigned["redacted_by"] = redaction_id

            # It's fine to add the event directly, since get_pdu_json
            # will serialise this field correctly
            redacted_event.unsigned["redacted_because"] = redaction_event

            return redacted_event

        # no valid redaction found for this event
        return None

    @defer.inlineCallbacks
    def have_events_in_timeline(self, event_ids):
        """Given a list of event ids, check if we have already processed and
        stored them as non outliers.
        """
        rows = yield self.db.simple_select_many_batch(
            table="events",
            retcols=("event_id",),
            column="event_id",
            iterable=list(event_ids),
            keyvalues={"outlier": False},
            desc="have_events_in_timeline",
        )

        return {r["event_id"] for r in rows}

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
            sql = "SELECT event_id FROM events as e WHERE "
            clause, args = make_in_list_sql_clause(
                txn.database_engine, "e.event_id", chunk
            )
            txn.execute(sql + clause, args)
            for (event_id,) in txn:
                results.add(event_id)

        # break the input up into chunks of 100
        input_iterator = iter(event_ids)
        for chunk in iter(lambda: list(itertools.islice(input_iterator, 100)), []):
            yield self.db.runInteraction(
                "have_seen_events", have_seen_events_txn, chunk
            )
        return results

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
        return self.db.runInteraction(
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
        return self.db.runInteraction(
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

        return {"v1": complexity_v1}

    def get_current_backfill_token(self):
        """The current minimum token that backfilled events have reached"""
        return -self._backfill_id_gen.get_current_token()

    def get_current_events_token(self):
        """The current maximum token that events have reached"""
        return self._stream_id_gen.get_current_token()

    def get_all_new_forward_event_rows(self, last_id, current_id, limit):
        """Returns new events, for the Events replication stream

        Args:
            last_id: the last stream_id from the previous batch.
            current_id: the maximum stream_id to return up to
            limit: the maximum number of rows to return

        Returns: Deferred[List[Tuple]]
            a list of events stream rows. Each tuple consists of a stream id as
            the first element, followed by fields suitable for casting into an
            EventsStreamRow.
        """

        def get_all_new_forward_event_rows(txn):
            sql = (
                "SELECT e.stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts, relates_to_id"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " LEFT JOIN event_relations USING (event_id)"
                " WHERE ? < stream_ordering AND stream_ordering <= ?"
                " ORDER BY stream_ordering ASC"
                " LIMIT ?"
            )
            txn.execute(sql, (last_id, current_id, limit))
            return txn.fetchall()

        return self.db.runInteraction(
            "get_all_new_forward_event_rows", get_all_new_forward_event_rows
        )

    def get_ex_outlier_stream_rows(self, last_id, current_id):
        """Returns de-outliered events, for the Events replication stream

        Args:
            last_id: the last stream_id from the previous batch.
            current_id: the maximum stream_id to return up to

        Returns: Deferred[List[Tuple]]
            a list of events stream rows. Each tuple consists of a stream id as
            the first element, followed by fields suitable for casting into an
            EventsStreamRow.
        """

        def get_ex_outlier_stream_rows_txn(txn):
            sql = (
                "SELECT event_stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts, relates_to_id"
                " FROM events AS e"
                " INNER JOIN ex_outlier_stream USING (event_id)"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " LEFT JOIN event_relations USING (event_id)"
                " WHERE ? < event_stream_ordering"
                " AND event_stream_ordering <= ?"
                " ORDER BY event_stream_ordering ASC"
            )

            txn.execute(sql, (last_id, current_id))
            return txn.fetchall()

        return self.db.runInteraction(
            "get_ex_outlier_stream_rows", get_ex_outlier_stream_rows_txn
        )

    def get_all_new_backfill_event_rows(self, last_id, current_id, limit):
        if last_id == current_id:
            return defer.succeed([])

        def get_all_new_backfill_event_rows(txn):
            sql = (
                "SELECT -e.stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts, relates_to_id"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " LEFT JOIN event_relations USING (event_id)"
                " WHERE ? > stream_ordering AND stream_ordering >= ?"
                " ORDER BY stream_ordering ASC"
                " LIMIT ?"
            )
            txn.execute(sql, (-last_id, -current_id, limit))
            new_event_updates = txn.fetchall()

            if len(new_event_updates) == limit:
                upper_bound = new_event_updates[-1][0]
            else:
                upper_bound = current_id

            sql = (
                "SELECT -event_stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts, relates_to_id"
                " FROM events AS e"
                " INNER JOIN ex_outlier_stream USING (event_id)"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " LEFT JOIN event_relations USING (event_id)"
                " WHERE ? > event_stream_ordering"
                " AND event_stream_ordering >= ?"
                " ORDER BY event_stream_ordering DESC"
            )
            txn.execute(sql, (-last_id, -upper_bound))
            new_event_updates.extend(txn.fetchall())

            return new_event_updates

        return self.db.runInteraction(
            "get_all_new_backfill_event_rows", get_all_new_backfill_event_rows
        )

    async def get_all_updated_current_state_deltas(
        self, from_token: int, to_token: int, target_row_count: int
    ) -> Tuple[List[Tuple], int, bool]:
        """Fetch updates from current_state_delta_stream

        Args:
            from_token: The previous stream token. Updates from this stream id will
                be excluded.

            to_token: The current stream token (ie the upper limit). Updates up to this
                stream id will be included (modulo the 'limit' param)

            target_row_count: The number of rows to try to return. If more rows are
                available, we will set 'limited' in the result. In the event of a large
                batch, we may return more rows than this.
        Returns:
            A triplet `(updates, new_last_token, limited)`, where:
               * `updates` is a list of database tuples.
               * `new_last_token` is the new position in stream.
               * `limited` is whether there are more updates to fetch.
        """

        def get_all_updated_current_state_deltas_txn(txn):
            sql = """
                SELECT stream_id, room_id, type, state_key, event_id
                FROM current_state_delta_stream
                WHERE ? < stream_id AND stream_id <= ?
                ORDER BY stream_id ASC LIMIT ?
            """
            txn.execute(sql, (from_token, to_token, target_row_count))
            return txn.fetchall()

        def get_deltas_for_stream_id_txn(txn, stream_id):
            sql = """
                SELECT stream_id, room_id, type, state_key, event_id
                FROM current_state_delta_stream
                WHERE stream_id = ?
            """
            txn.execute(sql, [stream_id])
            return txn.fetchall()

        # we need to make sure that, for every stream id in the results, we get *all*
        # the rows with that stream id.

        rows = await self.db.runInteraction(
            "get_all_updated_current_state_deltas",
            get_all_updated_current_state_deltas_txn,
        )  # type: List[Tuple]

        # if we've got fewer rows than the limit, we're good
        if len(rows) < target_row_count:
            return rows, to_token, False

        # we hit the limit, so reduce the upper limit so that we exclude the stream id
        # of the last row in the result.
        assert rows[-1][0] <= to_token
        to_token = rows[-1][0] - 1

        # search backwards through the list for the point to truncate
        for idx in range(len(rows) - 1, 0, -1):
            if rows[idx - 1][0] <= to_token:
                return rows[:idx], to_token, True

        # bother. We didn't get a full set of changes for even a single
        # stream id. let's run the query again, without a row limit, but for
        # just one stream id.
        to_token += 1
        rows = await self.db.runInteraction(
            "get_deltas_for_stream_id", get_deltas_for_stream_id_txn, to_token
        )

        return rows, to_token, True

    @cached(num_args=5, max_entries=10)
    def get_all_new_events(
        self,
        last_backfill_id,
        last_forward_id,
        current_backfill_id,
        current_forward_id,
        limit,
    ):
        """Get all the new events that have arrived at the server either as
        new events or as backfilled events"""
        have_backfill_events = last_backfill_id != current_backfill_id
        have_forward_events = last_forward_id != current_forward_id

        if not have_backfill_events and not have_forward_events:
            return defer.succeed(AllNewEventsResult([], [], [], [], []))

        def get_all_new_events_txn(txn):
            sql = (
                "SELECT e.stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " WHERE ? < stream_ordering AND stream_ordering <= ?"
                " ORDER BY stream_ordering ASC"
                " LIMIT ?"
            )
            if have_forward_events:
                txn.execute(sql, (last_forward_id, current_forward_id, limit))
                new_forward_events = txn.fetchall()

                if len(new_forward_events) == limit:
                    upper_bound = new_forward_events[-1][0]
                else:
                    upper_bound = current_forward_id

                sql = (
                    "SELECT event_stream_ordering, event_id, state_group"
                    " FROM ex_outlier_stream"
                    " WHERE ? > event_stream_ordering"
                    " AND event_stream_ordering >= ?"
                    " ORDER BY event_stream_ordering DESC"
                )
                txn.execute(sql, (last_forward_id, upper_bound))
                forward_ex_outliers = txn.fetchall()
            else:
                new_forward_events = []
                forward_ex_outliers = []

            sql = (
                "SELECT -e.stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " WHERE ? > stream_ordering AND stream_ordering >= ?"
                " ORDER BY stream_ordering DESC"
                " LIMIT ?"
            )
            if have_backfill_events:
                txn.execute(sql, (-last_backfill_id, -current_backfill_id, limit))
                new_backfill_events = txn.fetchall()

                if len(new_backfill_events) == limit:
                    upper_bound = new_backfill_events[-1][0]
                else:
                    upper_bound = current_backfill_id

                sql = (
                    "SELECT -event_stream_ordering, event_id, state_group"
                    " FROM ex_outlier_stream"
                    " WHERE ? > event_stream_ordering"
                    " AND event_stream_ordering >= ?"
                    " ORDER BY event_stream_ordering DESC"
                )
                txn.execute(sql, (-last_backfill_id, -upper_bound))
                backward_ex_outliers = txn.fetchall()
            else:
                new_backfill_events = []
                backward_ex_outliers = []

            return AllNewEventsResult(
                new_forward_events,
                new_backfill_events,
                forward_ex_outliers,
                backward_ex_outliers,
            )

        return self.db.runInteraction("get_all_new_events", get_all_new_events_txn)

    async def is_event_after(self, event_id1, event_id2):
        """Returns True if event_id1 is after event_id2 in the stream
        """
        to_1, so_1 = await self.get_event_ordering(event_id1)
        to_2, so_2 = await self.get_event_ordering(event_id2)
        return (to_1, so_1) > (to_2, so_2)

    @cachedInlineCallbacks(max_entries=5000)
    def get_event_ordering(self, event_id):
        res = yield self.db.simple_select_one(
            table="events",
            retcols=["topological_ordering", "stream_ordering"],
            keyvalues={"event_id": event_id},
            allow_none=True,
        )

        if not res:
            raise SynapseError(404, "Could not find event %s" % (event_id,))

        return (int(res["topological_ordering"]), int(res["stream_ordering"]))

    def get_next_event_to_expire(self):
        """Retrieve the entry with the lowest expiry timestamp in the event_expiry
        table, or None if there's no more event to expire.

        Returns: Deferred[Optional[Tuple[str, int]]]
            A tuple containing the event ID as its first element and an expiry timestamp
            as its second one, if there's at least one row in the event_expiry table.
            None otherwise.
        """

        def get_next_event_to_expire_txn(txn):
            txn.execute(
                """
                SELECT event_id, expiry_ts FROM event_expiry
                ORDER BY expiry_ts ASC LIMIT 1
                """
            )

            return txn.fetchone()

        return self.db.runInteraction(
            desc="get_next_event_to_expire", func=get_next_event_to_expire_txn
        )


AllNewEventsResult = namedtuple(
    "AllNewEventsResult",
    [
        "new_forward_events",
        "new_backfill_events",
        "forward_ex_outliers",
        "backward_ex_outliers",
    ],
)
