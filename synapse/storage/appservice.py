# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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
import simplejson as json
from twisted.internet import defer

from synapse.api.constants import Membership
from synapse.appservice import AppServiceTransaction
from synapse.config.appservice import load_appservices
from synapse.storage.roommember import RoomsForUser
from ._base import SQLBaseStore


logger = logging.getLogger(__name__)


class ApplicationServiceStore(SQLBaseStore):

    def __init__(self, hs):
        super(ApplicationServiceStore, self).__init__(hs)
        self.hostname = hs.hostname
        self.services_cache = load_appservices(
            hs.hostname,
            hs.config.app_service_config_files
        )

    def get_app_services(self):
        return self.services_cache

    def get_if_app_services_interested_in_user(self, user_id):
        """Check if the user is one associated with an app service
        """
        for service in self.services_cache:
            if service.is_interested_in_user(user_id):
                return True
        return False

    def get_app_service_by_user_id(self, user_id):
        """Retrieve an application service from their user ID.

        All application services have associated with them a particular user ID.
        There is no distinguishing feature on the user ID which indicates it
        represents an application service. This function allows you to map from
        a user ID to an application service.

        Args:
            user_id(str): The user ID to see if it is an application service.
        Returns:
            synapse.appservice.ApplicationService or None.
        """
        for service in self.services_cache:
            if service.sender == user_id:
                return service
        return None

    def get_app_service_by_token(self, token):
        """Get the application service with the given appservice token.

        Args:
            token (str): The application service token.
        Returns:
            synapse.appservice.ApplicationService or None.
        """
        for service in self.services_cache:
            if service.token == token:
                return service
        return None

    def get_app_service_rooms(self, service):
        """Get a list of RoomsForUser for this application service.

        Application services may be "interested" in lots of rooms depending on
        the room ID, the room aliases, or the members in the room. This function
        takes all of these into account and returns a list of RoomsForUser which
        represent the entire list of room IDs that this application service
        wants to know about.

        Args:
            service: The application service to get a room list for.
        Returns:
            A list of RoomsForUser.
        """
        return self.runInteraction(
            "get_app_service_rooms",
            self._get_app_service_rooms_txn,
            service,
        )

    def _get_app_service_rooms_txn(self, txn, service):
        # get all rooms matching the room ID regex.
        room_entries = self._simple_select_list_txn(
            txn=txn, table="rooms", keyvalues=None, retcols=["room_id"]
        )
        matching_room_list = set([
            r["room_id"] for r in room_entries if
            service.is_interested_in_room(r["room_id"])
        ])

        # resolve room IDs for matching room alias regex.
        room_alias_mappings = self._simple_select_list_txn(
            txn=txn, table="room_aliases", keyvalues=None,
            retcols=["room_id", "room_alias"]
        )
        matching_room_list |= set([
            r["room_id"] for r in room_alias_mappings if
            service.is_interested_in_alias(r["room_alias"])
        ])

        # get all rooms for every user for this AS. This is scoped to users on
        # this HS only.
        user_list = self._simple_select_list_txn(
            txn=txn, table="users", keyvalues=None, retcols=["name"]
        )
        user_list = [
            u["name"] for u in user_list if
            service.is_interested_in_user(u["name"])
        ]
        rooms_for_user_matching_user_id = set()  # RoomsForUser list
        for user_id in user_list:
            # FIXME: This assumes this store is linked with RoomMemberStore :(
            rooms_for_user = self._get_rooms_for_user_where_membership_is_txn(
                txn=txn,
                user_id=user_id,
                membership_list=[Membership.JOIN]
            )
            rooms_for_user_matching_user_id |= set(rooms_for_user)

        # make RoomsForUser tuples for room ids and aliases which are not in the
        # main rooms_for_user_list - e.g. they are rooms which do not have AS
        # registered users in it.
        known_room_ids = [r.room_id for r in rooms_for_user_matching_user_id]
        missing_rooms_for_user = [
            RoomsForUser(r, service.sender, "join") for r in
            matching_room_list if r not in known_room_ids
        ]
        rooms_for_user_matching_user_id |= set(missing_rooms_for_user)

        return rooms_for_user_matching_user_id


class ApplicationServiceTransactionStore(SQLBaseStore):

    def __init__(self, hs):
        super(ApplicationServiceTransactionStore, self).__init__(hs)

    @defer.inlineCallbacks
    def get_appservices_by_state(self, state):
        """Get a list of application services based on their state.

        Args:
            state(ApplicationServiceState): The state to filter on.
        Returns:
            A Deferred which resolves to a list of ApplicationServices, which
            may be empty.
        """
        results = yield self._simple_select_list(
            "application_services_state",
            dict(state=state),
            ["as_id"]
        )
        # NB: This assumes this class is linked with ApplicationServiceStore
        as_list = self.get_app_services()
        services = []

        for res in results:
            for service in as_list:
                if service.id == res["as_id"]:
                    services.append(service)
        defer.returnValue(services)

    @defer.inlineCallbacks
    def get_appservice_state(self, service):
        """Get the application service state.

        Args:
            service(ApplicationService): The service whose state to set.
        Returns:
            A Deferred which resolves to ApplicationServiceState.
        """
        result = yield self._simple_select_one(
            "application_services_state",
            dict(as_id=service.id),
            ["state"],
            allow_none=True,
            desc="get_appservice_state",
        )
        if result:
            defer.returnValue(result.get("state"))
            return
        defer.returnValue(None)

    def set_appservice_state(self, service, state):
        """Set the application service state.

        Args:
            service(ApplicationService): The service whose state to set.
            state(ApplicationServiceState): The connectivity state to apply.
        Returns:
            A Deferred which resolves when the state was set successfully.
        """
        return self._simple_upsert(
            "application_services_state",
            dict(as_id=service.id),
            dict(state=state)
        )

    def create_appservice_txn(self, service, events):
        """Atomically creates a new transaction for this application service
        with the given list of events.

        Args:
            service(ApplicationService): The service who the transaction is for.
            events(list<Event>): A list of events to put in the transaction.
        Returns:
            AppServiceTransaction: A new transaction.
        """
        def _create_appservice_txn(txn):
            # work out new txn id (highest txn id for this service += 1)
            # The highest id may be the last one sent (in which case it is last_txn)
            # or it may be the highest in the txns list (which are waiting to be/are
            # being sent)
            last_txn_id = self._get_last_txn(txn, service.id)

            txn.execute(
                "SELECT MAX(txn_id) FROM application_services_txns WHERE as_id=?",
                (service.id,)
            )
            highest_txn_id = txn.fetchone()[0]
            if highest_txn_id is None:
                highest_txn_id = 0

            new_txn_id = max(highest_txn_id, last_txn_id) + 1

            # Insert new txn into txn table
            event_ids = json.dumps([e.event_id for e in events])
            txn.execute(
                "INSERT INTO application_services_txns(as_id, txn_id, event_ids) "
                "VALUES(?,?,?)",
                (service.id, new_txn_id, event_ids)
            )
            return AppServiceTransaction(
                service=service, id=new_txn_id, events=events
            )

        return self.runInteraction(
            "create_appservice_txn",
            _create_appservice_txn,
        )

    def complete_appservice_txn(self, txn_id, service):
        """Completes an application service transaction.

        Args:
            txn_id(str): The transaction ID being completed.
            service(ApplicationService): The application service which was sent
            this transaction.
        Returns:
            A Deferred which resolves if this transaction was stored
            successfully.
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
                    "completing_txn=%s service_id=%s", last_txn_id, txn_id,
                    service.id
                )

            # Set current txn_id for AS to 'txn_id'
            self._simple_upsert_txn(
                txn, "application_services_state", dict(as_id=service.id),
                dict(last_txn=txn_id)
            )

            # Delete txn
            self._simple_delete_txn(
                txn, "application_services_txns",
                dict(txn_id=txn_id, as_id=service.id)
            )

        return self.runInteraction(
            "complete_appservice_txn",
            _complete_appservice_txn,
        )

    @defer.inlineCallbacks
    def get_oldest_unsent_txn(self, service):
        """Get the oldest transaction which has not been sent for this
        service.

        Args:
            service(ApplicationService): The app service to get the oldest txn.
        Returns:
            A Deferred which resolves to an AppServiceTransaction or
            None.
        """
        def _get_oldest_unsent_txn(txn):
            # Monotonically increasing txn ids, so just select the smallest
            # one in the txns table (we delete them when they are sent)
            txn.execute(
                "SELECT * FROM application_services_txns WHERE as_id=?"
                " ORDER BY txn_id ASC LIMIT 1",
                (service.id,)
            )
            rows = self.cursor_to_dict(txn)
            if not rows:
                return None

            entry = rows[0]

            return entry

        entry = yield self.runInteraction(
            "get_oldest_unsent_appservice_txn",
            _get_oldest_unsent_txn,
        )

        if not entry:
            defer.returnValue(None)

        event_ids = json.loads(entry["event_ids"])

        events = yield self._get_events(event_ids)

        defer.returnValue(AppServiceTransaction(
            service=service, id=entry["txn_id"], events=events
        ))

    def _get_last_txn(self, txn, service_id):
        txn.execute(
            "SELECT last_txn FROM application_services_state WHERE as_id=?",
            (service_id,)
        )
        last_txn_id = txn.fetchone()
        if last_txn_id is None or last_txn_id[0] is None:  # no row exists
            return 0
        else:
            return int(last_txn_id[0])  # select 'last_txn' col

    def set_appservice_last_pos(self, pos):
        def set_appservice_last_pos_txn(txn):
            txn.execute(
                "UPDATE appservice_stream_position SET stream_ordering = ?", (pos,)
            )
        return self.runInteraction(
            "set_appservice_last_pos", set_appservice_last_pos_txn
        )

    @defer.inlineCallbacks
    def get_new_events_for_appservice(self, current_id, limit):
        """Get all new evnets"""

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

        upper_bound, event_ids = yield self.runInteraction(
            "get_new_events_for_appservice", get_new_events_for_appservice_txn,
        )

        events = yield self._get_events(event_ids)

        defer.returnValue((upper_bound, events))
