# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from _base import SQLBaseStore, _RollbackButIsFineException

from twisted.internet import defer, reactor

from synapse.events import FrozenEvent
from synapse.events.utils import prune_event
from synapse.util import unwrap_deferred

from synapse.util.logcontext import preserve_context_over_deferred
from synapse.util.logutils import log_function
from synapse.api.constants import EventTypes
from synapse.crypto.event_signing import compute_event_reference_hash

from syutil.base64util import decode_base64
from syutil.jsonutil import encode_canonical_json
from contextlib import contextmanager

import logging
import simplejson as json

logger = logging.getLogger(__name__)


class EventsStore(SQLBaseStore):
    @defer.inlineCallbacks
    @log_function
    def persist_event(self, event, context, backfilled=False,
                      is_new_state=True, current_state=None):
        stream_ordering = None
        if backfilled:
            if not self.min_token_deferred.called:
                yield self.min_token_deferred
            self.min_token -= 1
            stream_ordering = self.min_token

        if stream_ordering is None:
            stream_ordering_manager = yield self._stream_id_gen.get_next(self)
        else:
            @contextmanager
            def stream_ordering_manager():
                yield stream_ordering
            stream_ordering_manager = stream_ordering_manager()

        try:
            with stream_ordering_manager as stream_ordering:
                yield self.runInteraction(
                    "persist_event",
                    self._persist_event_txn,
                    event=event,
                    context=context,
                    backfilled=backfilled,
                    stream_ordering=stream_ordering,
                    is_new_state=is_new_state,
                    current_state=current_state,
                )
        except _RollbackButIsFineException:
            pass

    @defer.inlineCallbacks
    def get_event(self, event_id, check_redacted=True,
                  get_prev_content=False, allow_rejected=False,
                  allow_none=False):
        """Get an event from the database by event_id.

        Args:
            event_id (str): The event_id of the event to fetch
            check_redacted (bool): If True, check if event has been redacted
                and redact it.
            get_prev_content (bool): If True and event is a state event,
                include the previous states content in the unsigned field.
            allow_rejected (bool): If True return rejected events.
            allow_none (bool): If True, return None if no event found, if
                False throw an exception.

        Returns:
            Deferred : A FrozenEvent.
        """
        events = yield self._get_events(
            [event_id],
            check_redacted=check_redacted,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        if not events and not allow_none:
            raise RuntimeError("Could not find event %s" % (event_id,))

        defer.returnValue(events[0] if events else None)

    @log_function
    def _persist_event_txn(self, txn, event, context, backfilled,
                           stream_ordering=None, is_new_state=True,
                           current_state=None):

        # Remove the any existing cache entries for the event_id
        txn.call_after(self._invalidate_get_event_cache, event.event_id)

        # We purposefully do this first since if we include a `current_state`
        # key, we *want* to update the `current_state_events` table
        if current_state:
            self._simple_delete_txn(
                txn,
                table="current_state_events",
                keyvalues={"room_id": event.room_id},
            )

            for s in current_state:
                if s.type == EventTypes.Member:
                    txn.call_after(
                        self.get_rooms_for_user.invalidate, s.state_key
                    )
                    txn.call_after(
                        self.get_joined_hosts_for_room.invalidate, s.room_id
                    )
                self._simple_insert_txn(
                    txn,
                    "current_state_events",
                    {
                        "event_id": s.event_id,
                        "room_id": s.room_id,
                        "type": s.type,
                        "state_key": s.state_key,
                    }
                )

        outlier = event.internal_metadata.is_outlier()

        if not outlier:
            self._update_min_depth_for_room_txn(
                txn,
                event.room_id,
                event.depth
            )

        have_persisted = self._simple_select_one_txn(
            txn,
            table="events",
            keyvalues={"event_id": event.event_id},
            retcols=["event_id", "outlier"],
            allow_none=True,
        )

        metadata_json = encode_canonical_json(
            event.internal_metadata.get_dict()
        ).decode("UTF-8")

        # If we have already persisted this event, we don't need to do any
        # more processing.
        # The processing above must be done on every call to persist event,
        # since they might not have happened on previous calls. For example,
        # if we are persisting an event that we had persisted as an outlier,
        # but is no longer one.
        if have_persisted:
            if not outlier and have_persisted["outlier"]:
                self._store_state_groups_txn(txn, event, context)

                sql = (
                    "UPDATE event_json SET internal_metadata = ?"
                    " WHERE event_id = ?"
                )
                txn.execute(
                    sql,
                    (metadata_json, event.event_id,)
                )

                sql = (
                    "UPDATE events SET outlier = ?"
                    " WHERE event_id = ?"
                )
                txn.execute(
                    sql,
                    (False, event.event_id,)
                )
            return

        if not outlier:
            self._store_state_groups_txn(txn, event, context)

        self._handle_prev_events(
            txn,
            outlier=outlier,
            event_id=event.event_id,
            prev_events=event.prev_events,
            room_id=event.room_id,
        )

        if event.type == EventTypes.Member:
            self._store_room_member_txn(txn, event)
        elif event.type == EventTypes.Name:
            self._store_room_name_txn(txn, event)
        elif event.type == EventTypes.Topic:
            self._store_room_topic_txn(txn, event)
        elif event.type == EventTypes.Redaction:
            self._store_redaction(txn, event)

        event_dict = {
            k: v
            for k, v in event.get_dict().items()
            if k not in [
                "redacted",
                "redacted_because",
            ]
        }

        self._simple_insert_txn(
            txn,
            table="event_json",
            values={
                "event_id": event.event_id,
                "room_id": event.room_id,
                "internal_metadata": metadata_json,
                "json": encode_canonical_json(event_dict).decode("UTF-8"),
            },
        )

        content = encode_canonical_json(
            event.content
        ).decode("UTF-8")

        vals = {
            "topological_ordering": event.depth,
            "event_id": event.event_id,
            "type": event.type,
            "room_id": event.room_id,
            "content": content,
            "processed": True,
            "outlier": outlier,
            "depth": event.depth,
        }

        unrec = {
            k: v
            for k, v in event.get_dict().items()
            if k not in vals.keys() and k not in [
                "redacted",
                "redacted_because",
                "signatures",
                "hashes",
                "prev_events",
            ]
        }

        vals["unrecognized_keys"] = encode_canonical_json(
            unrec
        ).decode("UTF-8")

        sql = (
            "INSERT INTO events"
            " (stream_ordering, topological_ordering, event_id, type,"
            " room_id, content, processed, outlier, depth)"
            " VALUES (?,?,?,?,?,?,?,?,?)"
        )

        txn.execute(
            sql,
            (
                stream_ordering, event.depth, event.event_id, event.type,
                event.room_id, content, True, outlier, event.depth
            )
        )

        if context.rejected:
            self._store_rejections_txn(
                txn, event.event_id, context.rejected
            )

        for hash_alg, hash_base64 in event.hashes.items():
            hash_bytes = decode_base64(hash_base64)
            self._store_event_content_hash_txn(
                txn, event.event_id, hash_alg, hash_bytes,
            )

        for prev_event_id, prev_hashes in event.prev_events:
            for alg, hash_base64 in prev_hashes.items():
                hash_bytes = decode_base64(hash_base64)
                self._store_prev_event_hash_txn(
                    txn, event.event_id, prev_event_id, alg,
                    hash_bytes
                )

        self._simple_insert_many_txn(
            txn,
            table="event_auth",
            values=[
                {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "auth_id": auth_id,
                }
                for auth_id, _ in event.auth_events
            ],
        )

        (ref_alg, ref_hash_bytes) = compute_event_reference_hash(event)
        self._store_event_reference_hash_txn(
            txn, event.event_id, ref_alg, ref_hash_bytes
        )

        if event.is_state():
            vals = {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "type": event.type,
                "state_key": event.state_key,
            }

            # TODO: How does this work with backfilling?
            if hasattr(event, "replaces_state"):
                vals["prev_state"] = event.replaces_state

            self._simple_insert_txn(
                txn,
                "state_events",
                vals,
            )

            self._simple_insert_many_txn(
                txn,
                table="event_edges",
                values=[
                    {
                        "event_id": event.event_id,
                        "prev_event_id": e_id,
                        "room_id": event.room_id,
                        "is_state": True,
                    }
                    for e_id, h in event.prev_state
                ],
            )

            if is_new_state and not context.rejected:
                self._simple_upsert_txn(
                    txn,
                    "current_state_events",
                    keyvalues={
                        "room_id": event.room_id,
                        "type": event.type,
                        "state_key": event.state_key,
                    },
                    values={
                        "event_id": event.event_id,
                    }
                )

        return

    def _store_redaction(self, txn, event):
        # invalidate the cache for the redacted event
        txn.call_after(self._invalidate_get_event_cache, event.redacts)
        txn.execute(
            "INSERT INTO redactions (event_id, redacts) VALUES (?,?)",
            (event.event_id, event.redacts)
        )

    def have_events(self, event_ids):
        """Given a list of event ids, check if we have already processed them.

        Returns:
            dict: Has an entry for each event id we already have seen. Maps to
            the rejected reason string if we rejected the event, else maps to
            None.
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

        return self.runInteraction(
            "have_events", f,
        )

    @defer.inlineCallbacks
    def _get_events(self, event_ids, check_redacted=True,
                    get_prev_content=False, allow_rejected=False, txn=None):
        """Gets a collection of events. If `txn` is not None the we use the
        current transaction to fetch events and we return a deferred that is
        guarenteed to have resolved.
        """
        if not event_ids:
            defer.returnValue([])

        event_map = self._get_events_from_cache(
            event_ids,
            check_redacted=check_redacted,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        missing_events_ids = [e for e in event_ids if e not in event_map]

        if not missing_events_ids:
            defer.returnValue([
                event_map[e_id] for e_id in event_ids
                if e_id in event_map and event_map[e_id]
            ])

        if not txn:
            missing_events = yield self._enqueue_events(
                missing_events_ids,
                check_redacted=check_redacted,
                get_prev_content=get_prev_content,
                allow_rejected=allow_rejected,
            )
        else:
            missing_events = self._fetch_events_txn(
                txn,
                missing_events_ids,
                check_redacted=check_redacted,
                get_prev_content=get_prev_content,
                allow_rejected=allow_rejected,
            )

        event_map.update(missing_events)

        defer.returnValue([
            event_map[e_id] for e_id in event_ids
            if e_id in event_map and event_map[e_id]
        ])

    def _get_events_txn(self, txn, event_ids, check_redacted=True,
                        get_prev_content=False, allow_rejected=False):
        return unwrap_deferred(self._get_events(
            event_ids,
            check_redacted=check_redacted,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
            txn=txn,
        ))

    def _invalidate_get_event_cache(self, event_id):
        for check_redacted in (False, True):
            for get_prev_content in (False, True):
                self._get_event_cache.invalidate(event_id, check_redacted,
                                                 get_prev_content)

    def _get_event_txn(self, txn, event_id, check_redacted=True,
                       get_prev_content=False, allow_rejected=False):

        events = self._get_events_txn(
            txn, [event_id],
            check_redacted=check_redacted,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        return events[0] if events else None

    def _get_events_from_cache(self, events, check_redacted, get_prev_content,
                               allow_rejected):
        event_map = {}

        for event_id in events:
            try:
                ret = self._get_event_cache.get(
                    event_id, check_redacted, get_prev_content
                )

                if allow_rejected or not ret.rejected_reason:
                    event_map[event_id] = ret
                else:
                    event_map[event_id] = None
            except KeyError:
                pass

        return event_map

    def _do_fetch(self, conn):
        """Takes a database connection and waits for requests for events from
        the _event_fetch_list queue.
        """
        event_list = []
        i = 0
        while True:
            try:
                with self._event_fetch_lock:
                    event_list = self._event_fetch_list
                    self._event_fetch_list = []

                    if not event_list:
                        if self.database_engine.single_threaded or i > 3:
                            self._event_fetch_ongoing -= 1
                            return
                        else:
                            self._event_fetch_lock.wait(0.1)
                            i += 1
                            continue
                    i = 0

                event_id_lists = zip(*event_list)[0]
                event_ids = [
                    item for sublist in event_id_lists for item in sublist
                ]

                rows = self._new_transaction(
                    conn, "do_fetch", [], self._fetch_event_rows, event_ids
                )

                row_dict = {
                    r["event_id"]: r
                    for r in rows
                }

                # We only want to resolve deferreds from the main thread
                def fire(lst, res):
                    for ids, d in lst:
                        if not d.called:
                            try:
                                d.callback([
                                    res[i]
                                    for i in ids
                                    if i in res
                                ])
                            except:
                                logger.exception("Failed to callback")
                reactor.callFromThread(fire, event_list, row_dict)
            except Exception as e:
                logger.exception("do_fetch")

                # We only want to resolve deferreds from the main thread
                def fire(evs):
                    for _, d in evs:
                        if not d.called:
                            d.errback(e)

                if event_list:
                    reactor.callFromThread(fire, event_list)

    @defer.inlineCallbacks
    def _enqueue_events(self, events, check_redacted=True,
                        get_prev_content=False, allow_rejected=False):
        """Fetches events from the database using the _event_fetch_list. This
        allows batch and bulk fetching of events - it allows us to fetch events
        without having to create a new transaction for each request for events.
        """
        if not events:
            defer.returnValue({})

        events_d = defer.Deferred()
        with self._event_fetch_lock:
            self._event_fetch_list.append(
                (events, events_d)
            )

            self._event_fetch_lock.notify()

            if self._event_fetch_ongoing < 3:
                self._event_fetch_ongoing += 1
                should_start = True
            else:
                should_start = False

        if should_start:
            self.runWithConnection(
                self._do_fetch
            )

        rows = yield preserve_context_over_deferred(events_d)

        if not allow_rejected:
            rows[:] = [r for r in rows if not r["rejects"]]

        res = yield defer.gatherResults(
            [
                self._get_event_from_row(
                    row["internal_metadata"], row["json"], row["redacts"],
                    check_redacted=check_redacted,
                    get_prev_content=get_prev_content,
                    rejected_reason=row["rejects"],
                )
                for row in rows
            ],
            consumeErrors=True
        )

        defer.returnValue({
            e.event_id: e
            for e in res if e
        })

    def _fetch_event_rows(self, txn, events):
        rows = []
        N = 200
        for i in range(1 + len(events) / N):
            evs = events[i*N:(i + 1)*N]
            if not evs:
                break

            sql = (
                "SELECT "
                " e.event_id as event_id, "
                " e.internal_metadata,"
                " e.json,"
                " r.redacts as redacts,"
                " rej.event_id as rejects "
                " FROM event_json as e"
                " LEFT JOIN rejections as rej USING (event_id)"
                " LEFT JOIN redactions as r ON e.event_id = r.redacts"
                " WHERE e.event_id IN (%s)"
            ) % (",".join(["?"]*len(evs)),)

            txn.execute(sql, evs)
            rows.extend(self.cursor_to_dict(txn))

        return rows

    def _fetch_events_txn(self, txn, events, check_redacted=True,
                          get_prev_content=False, allow_rejected=False):
        if not events:
            return {}

        rows = self._fetch_event_rows(
            txn, events,
        )

        if not allow_rejected:
            rows[:] = [r for r in rows if not r["rejects"]]

        res = [
            self._get_event_from_row_txn(
                txn,
                row["internal_metadata"], row["json"], row["redacts"],
                check_redacted=check_redacted,
                get_prev_content=get_prev_content,
                rejected_reason=row["rejects"],
            )
            for row in rows
        ]

        return {
            r.event_id: r
            for r in res
        }

    @defer.inlineCallbacks
    def _get_event_from_row(self, internal_metadata, js, redacted,
                            check_redacted=True, get_prev_content=False,
                            rejected_reason=None):
        d = json.loads(js)
        internal_metadata = json.loads(internal_metadata)

        if rejected_reason:
            rejected_reason = yield self._simple_select_one_onecol(
                table="rejections",
                keyvalues={"event_id": rejected_reason},
                retcol="reason",
                desc="_get_event_from_row",
            )

        ev = FrozenEvent(
            d,
            internal_metadata_dict=internal_metadata,
            rejected_reason=rejected_reason,
        )

        if check_redacted and redacted:
            ev = prune_event(ev)

            redaction_id = yield self._simple_select_one_onecol(
                table="redactions",
                keyvalues={"redacts": ev.event_id},
                retcol="event_id",
                desc="_get_event_from_row",
            )

            ev.unsigned["redacted_by"] = redaction_id
            # Get the redaction event.

            because = yield self.get_event(
                redaction_id,
                check_redacted=False
            )

            if because:
                ev.unsigned["redacted_because"] = because

        if get_prev_content and "replaces_state" in ev.unsigned:
            prev = yield self.get_event(
                ev.unsigned["replaces_state"],
                get_prev_content=False,
            )
            if prev:
                ev.unsigned["prev_content"] = prev.get_dict()["content"]

        self._get_event_cache.prefill(
            ev.event_id, check_redacted, get_prev_content, ev
        )

        defer.returnValue(ev)

    def _get_event_from_row_txn(self, txn, internal_metadata, js, redacted,
                            check_redacted=True, get_prev_content=False,
                            rejected_reason=None):
        d = json.loads(js)
        internal_metadata = json.loads(internal_metadata)

        def select(txn, *args, **kwargs):
            if txn:
                return self._simple_select_one_onecol_txn(txn, *args, **kwargs)
            else:
                return self._simple_select_one_onecol(
                    *args,
                    desc="_get_event_from_row", **kwargs
                )

        def get_event(txn, *args, **kwargs):
            if txn:
                return self._get_event_txn(txn, *args, **kwargs)
            else:
                return self.get_event(*args, **kwargs)

        if rejected_reason:
            rejected_reason = yield select(
                txn,
                table="rejections",
                keyvalues={"event_id": rejected_reason},
                retcol="reason",
            )

        ev = FrozenEvent(
            d,
            internal_metadata_dict=internal_metadata,
            rejected_reason=rejected_reason,
        )

        if check_redacted and redacted:
            ev = prune_event(ev)

            redaction_id = yield select(
                txn,
                table="redactions",
                keyvalues={"redacts": ev.event_id},
                retcol="event_id",
            )

            ev.unsigned["redacted_by"] = redaction_id
            # Get the redaction event.

            because = yield get_event(
                txn,
                redaction_id,
                check_redacted=False
            )

            if because:
                ev.unsigned["redacted_because"] = because

        if get_prev_content and "replaces_state" in ev.unsigned:
            prev = yield get_event(
                txn,
                ev.unsigned["replaces_state"],
                get_prev_content=False,
            )
            if prev:
                ev.unsigned["prev_content"] = prev.get_dict()["content"]

        self._get_event_cache.prefill(
            ev.event_id, check_redacted, get_prev_content, ev
        )

        defer.returnValue(ev)

    def _parse_events(self, rows):
        return self.runInteraction(
            "_parse_events", self._parse_events_txn, rows
        )

    def _parse_events_txn(self, txn, rows):
        event_ids = [r["event_id"] for r in rows]

        return self._get_events_txn(txn, event_ids)

    def _has_been_redacted_txn(self, txn, event):
        sql = "SELECT event_id FROM redactions WHERE redacts = ?"
        txn.execute(sql, (event.event_id,))
        result = txn.fetchone()
        return result[0] if result else None
