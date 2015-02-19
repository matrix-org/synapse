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

from twisted.internet import defer

from synapse.util.logutils import log_function
from synapse.api.constants import EventTypes

from .appservice import ApplicationServiceStore
from .directory import DirectoryStore
from .feedback import FeedbackStore
from .presence import PresenceStore
from .profile import ProfileStore
from .registration import RegistrationStore
from .room import RoomStore
from .roommember import RoomMemberStore
from .stream import StreamStore
from .transactions import TransactionStore
from .keys import KeyStore
from .event_federation import EventFederationStore
from .pusher import PusherStore
from .push_rule import PushRuleStore
from .media_repository import MediaRepositoryStore
from .rejections import RejectionsStore

from .state import StateStore
from .signatures import SignatureStore
from .filtering import FilteringStore

from syutil.base64util import decode_base64
from syutil.jsonutil import encode_canonical_json

from synapse.crypto.event_signing import compute_event_reference_hash


import logging
import os


logger = logging.getLogger(__name__)


SCHEMAS = [
    "transactions",
    "users",
    "profiles",
    "presence",
    "im",
    "room_aliases",
    "keys",
    "redactions",
    "state",
    "event_edges",
    "event_signatures",
    "pusher",
    "media_repository",
    "application_services",
    "filtering",
    "rejections",
]


# Remember to update this number every time an incompatible change is made to
# database schema files, so the users will be informed on server restarts.
SCHEMA_VERSION = 13

dir_path = os.path.abspath(os.path.dirname(__file__))


class _RollbackButIsFineException(Exception):
    """ This exception is used to rollback a transaction without implying
    something went wrong.
    """
    pass


class DataStore(RoomMemberStore, RoomStore,
                RegistrationStore, StreamStore, ProfileStore, FeedbackStore,
                PresenceStore, TransactionStore,
                DirectoryStore, KeyStore, StateStore, SignatureStore,
                ApplicationServiceStore,
                EventFederationStore,
                MediaRepositoryStore,
                RejectionsStore,
                FilteringStore,
                PusherStore,
                PushRuleStore
                ):

    def __init__(self, hs):
        super(DataStore, self).__init__(hs)
        self.hs = hs

        self.min_token_deferred = self._get_min_token()
        self.min_token = None

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

        try:
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
        event = yield self.runInteraction(
            "get_event", self._get_event_txn,
            event_id,
            check_redacted=check_redacted,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        if not event and not allow_none:
            raise RuntimeError("Could not find event %s" % (event_id,))

        defer.returnValue(event)

    @log_function
    def _persist_event_txn(self, txn, event, context, backfilled,
                           stream_ordering=None, is_new_state=True,
                           current_state=None):

        # Remove the any existing cache entries for the event_id
        self._get_event_cache.pop(event.event_id)

        # We purposefully do this first since if we include a `current_state`
        # key, we *want* to update the `current_state_events` table
        if current_state:
            txn.execute(
                "DELETE FROM current_state_events WHERE room_id = ?",
                (event.room_id,)
            )

            for s in current_state:
                self._simple_insert_txn(
                    txn,
                    "current_state_events",
                    {
                        "event_id": s.event_id,
                        "room_id": s.room_id,
                        "type": s.type,
                        "state_key": s.state_key,
                    },
                    or_replace=True,
                )

        if event.is_state() and is_new_state:
            if not backfilled and not context.rejected:
                self._simple_insert_txn(
                    txn,
                    table="state_forward_extremities",
                    values={
                        "event_id": event.event_id,
                        "room_id": event.room_id,
                        "type": event.type,
                        "state_key": event.state_key,
                    },
                    or_replace=True,
                )

                for prev_state_id, _ in event.prev_state:
                    self._simple_delete_txn(
                        txn,
                        table="state_forward_extremities",
                        keyvalues={
                            "event_id": prev_state_id,
                        }
                    )

        outlier = event.internal_metadata.is_outlier()

        if not outlier:
            self._store_state_groups_txn(txn, event, context)

            self._update_min_depth_for_room_txn(
                txn,
                event.room_id,
                event.depth
            )

        self._handle_prev_events(
            txn,
            outlier=outlier,
            event_id=event.event_id,
            prev_events=event.prev_events,
            room_id=event.room_id,
        )

        have_persisted = self._simple_select_one_onecol_txn(
            txn,
            table="event_json",
            keyvalues={"event_id": event.event_id},
            retcol="event_id",
            allow_none=True,
        )

        metadata_json = encode_canonical_json(
            event.internal_metadata.get_dict()
        )

        # If we have already persisted this event, we don't need to do any
        # more processing.
        # The processing above must be done on every call to persist event,
        # since they might not have happened on previous calls. For example,
        # if we are persisting an event that we had persisted as an outlier,
        # but is no longer one.
        if have_persisted:
            if not outlier:
                sql = (
                    "UPDATE event_json SET internal_metadata = ?"
                    " WHERE event_id = ?"
                )
                txn.execute(
                    sql,
                    (metadata_json.decode("UTF-8"), event.event_id,)
                )

                sql = (
                    "UPDATE events SET outlier = 0"
                    " WHERE event_id = ?"
                )
                txn.execute(
                    sql,
                    (event.event_id,)
                )
            return

        if event.type == EventTypes.Member:
            self._store_room_member_txn(txn, event)
        elif event.type == EventTypes.Feedback:
            self._store_feedback_txn(txn, event)
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
                "internal_metadata": metadata_json.decode("UTF-8"),
                "json": encode_canonical_json(event_dict).decode("UTF-8"),
            },
            or_replace=True,
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

        if stream_ordering is not None:
            vals["stream_ordering"] = stream_ordering

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

        try:
            self._simple_insert_txn(
                txn,
                "events",
                vals,
                or_replace=(not outlier),
                or_ignore=bool(outlier),
            )
        except:
            logger.warn(
                "Failed to persist, probably duplicate: %s",
                event.event_id,
                exc_info=True,
            )
            raise _RollbackButIsFineException("_persist_event")

        if context.rejected:
            self._store_rejections_txn(txn, event.event_id, context.rejected)

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
                or_replace=True,
            )

            if is_new_state and not context.rejected:
                self._simple_insert_txn(
                    txn,
                    "current_state_events",
                    {
                        "event_id": event.event_id,
                        "room_id": event.room_id,
                        "type": event.type,
                        "state_key": event.state_key,
                    },
                    or_replace=True,
                )

            for e_id, h in event.prev_state:
                self._simple_insert_txn(
                    txn,
                    table="event_edges",
                    values={
                        "event_id": event.event_id,
                        "prev_event_id": e_id,
                        "room_id": event.room_id,
                        "is_state": 1,
                    },
                    or_ignore=True,
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
                    txn, event.event_id, prev_event_id, alg, hash_bytes
                )

        for auth_id, _ in event.auth_events:
            self._simple_insert_txn(
                txn,
                table="event_auth",
                values={
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "auth_id": auth_id,
                },
                or_ignore=True,
            )

        (ref_alg, ref_hash_bytes) = compute_event_reference_hash(event)
        self._store_event_reference_hash_txn(
            txn, event.event_id, ref_alg, ref_hash_bytes
        )

    def _store_redaction(self, txn, event):
        # invalidate the cache for the redacted event
        self._get_event_cache.pop(event.redacts)
        txn.execute(
            "INSERT OR IGNORE INTO redactions "
            "(event_id, redacts) VALUES (?,?)",
            (event.event_id, event.redacts)
        )

    @defer.inlineCallbacks
    def get_current_state(self, room_id, event_type=None, state_key=""):
        del_sql = (
            "SELECT event_id FROM redactions WHERE redacts = e.event_id "
            "LIMIT 1"
        )

        sql = (
            "SELECT e.*, (%(redacted)s) AS redacted FROM events as e "
            "INNER JOIN current_state_events as c ON e.event_id = c.event_id "
            "INNER JOIN state_events as s ON e.event_id = s.event_id "
            "WHERE c.room_id = ? "
        ) % {
            "redacted": del_sql,
        }

        if event_type and state_key is not None:
            sql += " AND s.type = ? AND s.state_key = ? "
            args = (room_id, event_type, state_key)
        elif event_type:
            sql += " AND s.type = ?"
            args = (room_id, event_type)
        else:
            args = (room_id, )

        results = yield self._execute_and_decode(sql, *args)

        events = yield self._parse_events(results)
        defer.returnValue(events)

    @defer.inlineCallbacks
    def get_room_name_and_aliases(self, room_id):
        del_sql = (
            "SELECT event_id FROM redactions WHERE redacts = e.event_id "
            "LIMIT 1"
        )

        sql = (
            "SELECT e.*, (%(redacted)s) AS redacted FROM events as e "
            "INNER JOIN current_state_events as c ON e.event_id = c.event_id "
            "INNER JOIN state_events as s ON e.event_id = s.event_id "
            "WHERE c.room_id = ? "
        ) % {
            "redacted": del_sql,
        }

        sql += " AND ((s.type = 'm.room.name' AND s.state_key = '')"
        sql += " OR s.type = 'm.room.aliases')"
        args = (room_id,)

        results = yield self._execute_and_decode(sql, *args)

        events = yield self._parse_events(results)

        name = None
        aliases = []

        for e in events:
            if e.type == 'm.room.name':
                name = e.content['name']
            elif e.type == 'm.room.aliases':
                aliases.extend(e.content['aliases'])

        defer.returnValue((name, aliases))

    @defer.inlineCallbacks
    def _get_min_token(self):
        row = yield self._execute(
            None,
            "SELECT MIN(stream_ordering) FROM events"
        )

        self.min_token = row[0][0] if row and row[0] and row[0][0] else -1
        self.min_token = min(self.min_token, -1)

        logger.debug("min_token is: %s", self.min_token)

        defer.returnValue(self.min_token)

    def insert_client_ip(self, user, access_token, device_id, ip, user_agent):
        return self._simple_insert(
            "user_ips",
            {
                "user": user.to_string(),
                "access_token": access_token,
                "device_id": device_id,
                "ip": ip,
                "user_agent": user_agent,
                "last_seen": int(self._clock.time_msec()),
            }
        )

    def get_user_ip_and_agents(self, user):
        return self._simple_select_list(
            table="user_ips",
            keyvalues={"user": user.to_string()},
            retcols=[
                "device_id", "access_token", "ip", "user_agent", "last_seen"
            ],
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


def schema_path(schema):
    """ Get a filesystem path for the named database schema

    Args:
        schema: Name of the database schema.
    Returns:
        A filesystem path pointing at a ".sql" file.

    """
    schemaPath = os.path.join(dir_path, "schema", schema + ".sql")
    return schemaPath


def read_schema(schema):
    """ Read the named database schema.

    Args:
        schema: Name of the datbase schema.
    Returns:
        A string containing the database schema.
    """
    with open(schema_path(schema)) as schema_file:
        return schema_file.read()


class PrepareDatabaseException(Exception):
    pass


class UpgradeDatabaseException(PrepareDatabaseException):
    pass


def prepare_database(db_conn):
    """ Set up all the dbs. Since all the *.sql have IF NOT EXISTS, so we
    don't have to worry about overwriting existing content.
    """
    c = db_conn.cursor()
    c.execute("PRAGMA user_version")
    row = c.fetchone()

    if row and row[0]:
        user_version = row[0]

        if user_version > SCHEMA_VERSION:
            raise ValueError(
                "Cannot use this database as it is too " +
                "new for the server to understand"
            )
        elif user_version < SCHEMA_VERSION:
            logger.info(
                "Upgrading database from version %d",
                user_version
            )

            # Run every version since after the current version.
            for v in range(user_version + 1, SCHEMA_VERSION + 1):
                if v == 10:
                    raise UpgradeDatabaseException(
                        "No delta for version 10"
                    )
                sql_script = read_schema("delta/v%d" % (v))
                c.executescript(sql_script)

            db_conn.commit()
        else:
            logger.info("Database is at version %r", user_version)

    else:
        sql_script = "BEGIN TRANSACTION;\n"
        for sql_loc in SCHEMAS:
            logger.debug("Applying schema %r", sql_loc)
            sql_script += read_schema(sql_loc)
            sql_script += "\n"
        sql_script += "COMMIT TRANSACTION;"
        c.executescript(sql_script)
        db_conn.commit()
        c.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)

    c.close()
