# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

import abc
import logging

from canonicaljson import json

from twisted.internet import defer

from synapse.push.baserules import list_with_base_rules
from synapse.storage.appservice import ApplicationServiceWorkerStore
from synapse.storage.pusher import PusherWorkerStore
from synapse.storage.receipts import ReceiptsWorkerStore
from synapse.storage.roommember import RoomMemberWorkerStore
from synapse.util.caches.descriptors import cachedInlineCallbacks, cachedList
from synapse.util.caches.stream_change_cache import StreamChangeCache

from ._base import SQLBaseStore

logger = logging.getLogger(__name__)


def _load_rules(rawrules, enabled_map):
    ruleslist = []
    for rawrule in rawrules:
        rule = dict(rawrule)
        rule["conditions"] = json.loads(rawrule["conditions"])
        rule["actions"] = json.loads(rawrule["actions"])
        ruleslist.append(rule)

    # We're going to be mutating this a lot, so do a deep copy
    rules = list(list_with_base_rules(ruleslist))

    for i, rule in enumerate(rules):
        rule_id = rule['rule_id']
        if rule_id in enabled_map:
            if rule.get('enabled', True) != bool(enabled_map[rule_id]):
                # Rules are cached across users.
                rule = dict(rule)
                rule['enabled'] = bool(enabled_map[rule_id])
                rules[i] = rule

    return rules


class PushRulesWorkerStore(
    ApplicationServiceWorkerStore,
    ReceiptsWorkerStore,
    PusherWorkerStore,
    RoomMemberWorkerStore,
    SQLBaseStore,
):
    """This is an abstract base class where subclasses must implement
    `get_max_push_rules_stream_id` which can be called in the initializer.
    """

    # This ABCMeta metaclass ensures that we cannot be instantiated without
    # the abstract methods being implemented.
    __metaclass__ = abc.ABCMeta

    def __init__(self, db_conn, hs):
        super(PushRulesWorkerStore, self).__init__(db_conn, hs)

        push_rules_prefill, push_rules_id = self._get_cache_dict(
            db_conn,
            "push_rules_stream",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=self.get_max_push_rules_stream_id(),
        )

        self.push_rules_stream_cache = StreamChangeCache(
            "PushRulesStreamChangeCache",
            push_rules_id,
            prefilled_cache=push_rules_prefill,
        )

    @abc.abstractmethod
    def get_max_push_rules_stream_id(self):
        """Get the position of the push rules stream.

        Returns:
            int
        """
        raise NotImplementedError()

    @cachedInlineCallbacks(max_entries=5000)
    def get_push_rules_for_user(self, user_id):
        rows = yield self._simple_select_list(
            table="push_rules",
            keyvalues={"user_name": user_id},
            retcols=(
                "user_name",
                "rule_id",
                "priority_class",
                "priority",
                "conditions",
                "actions",
            ),
            desc="get_push_rules_enabled_for_user",
        )

        rows.sort(key=lambda row: (-int(row["priority_class"]), -int(row["priority"])))

        enabled_map = yield self.get_push_rules_enabled_for_user(user_id)

        rules = _load_rules(rows, enabled_map)

        defer.returnValue(rules)

    @cachedInlineCallbacks(max_entries=5000)
    def get_push_rules_enabled_for_user(self, user_id):
        results = yield self._simple_select_list(
            table="push_rules_enable",
            keyvalues={'user_name': user_id},
            retcols=("user_name", "rule_id", "enabled"),
            desc="get_push_rules_enabled_for_user",
        )
        defer.returnValue(
            {r['rule_id']: False if r['enabled'] == 0 else True for r in results}
        )

    def have_push_rules_changed_for_user(self, user_id, last_id):
        if not self.push_rules_stream_cache.has_entity_changed(user_id, last_id):
            return defer.succeed(False)
        else:

            def have_push_rules_changed_txn(txn):
                sql = (
                    "SELECT COUNT(stream_id) FROM push_rules_stream"
                    " WHERE user_id = ? AND ? < stream_id"
                )
                txn.execute(sql, (user_id, last_id))
                count, = txn.fetchone()
                return bool(count)

            return self.runInteraction(
                "have_push_rules_changed", have_push_rules_changed_txn
            )

    @cachedList(
        cached_method_name="get_push_rules_for_user",
        list_name="user_ids",
        num_args=1,
        inlineCallbacks=True,
    )
    def bulk_get_push_rules(self, user_ids):
        if not user_ids:
            defer.returnValue({})

        results = {user_id: [] for user_id in user_ids}

        rows = yield self._simple_select_many_batch(
            table="push_rules",
            column="user_name",
            iterable=user_ids,
            retcols=("*",),
            desc="bulk_get_push_rules",
        )

        rows.sort(key=lambda row: (-int(row["priority_class"]), -int(row["priority"])))

        for row in rows:
            results.setdefault(row['user_name'], []).append(row)

        enabled_map_by_user = yield self.bulk_get_push_rules_enabled(user_ids)

        for user_id, rules in results.items():
            results[user_id] = _load_rules(rules, enabled_map_by_user.get(user_id, {}))

        defer.returnValue(results)

    @defer.inlineCallbacks
    def move_push_rule_from_room_to_room(self, new_room_id, user_id, rule):
        """Move a single push rule from one room to another for a specific user.

        Args:
            new_room_id (str): ID of the new room.
            user_id (str): ID of user the push rule belongs to.
            rule (Dict): A push rule.
        """
        # Create new rule id
        rule_id_scope = '/'.join(rule["rule_id"].split('/')[:-1])
        new_rule_id = rule_id_scope + "/" + new_room_id

        # Change room id in each condition
        for condition in rule.get("conditions", []):
            if condition.get("key") == "room_id":
                condition["pattern"] = new_room_id

        # Add the rule for the new room
        yield self.add_push_rule(
            user_id=user_id,
            rule_id=new_rule_id,
            priority_class=rule["priority_class"],
            conditions=rule["conditions"],
            actions=rule["actions"],
        )

        # Delete push rule for the old room
        yield self.delete_push_rule(user_id, rule["rule_id"])

    @defer.inlineCallbacks
    def move_push_rules_from_room_to_room_for_user(
        self, old_room_id, new_room_id, user_id
    ):
        """Move all of the push rules from one room to another for a specific
        user.

        Args:
            old_room_id (str): ID of the old room.
            new_room_id (str): ID of the new room.
            user_id (str): ID of user to copy push rules for.
        """
        # Retrieve push rules for this user
        user_push_rules = yield self.get_push_rules_for_user(user_id)

        # Get rules relating to the old room, move them to the new room, then
        # delete them from the old room
        for rule in user_push_rules:
            conditions = rule.get("conditions", [])
            if any(
                (c.get("key") == "room_id" and c.get("pattern") == old_room_id)
                for c in conditions
            ):
                self.move_push_rule_from_room_to_room(new_room_id, user_id, rule)

    @defer.inlineCallbacks
    def bulk_get_push_rules_for_room(self, event, context):
        state_group = context.state_group
        if not state_group:
            # If state_group is None it means it has yet to be assigned a
            # state group, i.e. we need to make sure that calls with a state_group
            # of None don't hit previous cached calls with a None state_group.
            # To do this we set the state_group to a new object as object() != object()
            state_group = object()

        current_state_ids = yield context.get_current_state_ids(self)
        result = yield self._bulk_get_push_rules_for_room(
            event.room_id, state_group, current_state_ids, event=event
        )
        defer.returnValue(result)

    @cachedInlineCallbacks(num_args=2, cache_context=True)
    def _bulk_get_push_rules_for_room(
        self, room_id, state_group, current_state_ids, cache_context, event=None
    ):
        # We don't use `state_group`, its there so that we can cache based
        # on it. However, its important that its never None, since two current_state's
        # with a state_group of None are likely to be different.
        # See bulk_get_push_rules_for_room for how we work around this.
        assert state_group is not None

        # We also will want to generate notifs for other people in the room so
        # their unread countss are correct in the event stream, but to avoid
        # generating them for bot / AS users etc, we only do so for people who've
        # sent a read receipt into the room.

        users_in_room = yield self._get_joined_users_from_context(
            room_id,
            state_group,
            current_state_ids,
            on_invalidate=cache_context.invalidate,
            event=event,
        )

        # We ignore app service users for now. This is so that we don't fill
        # up the `get_if_users_have_pushers` cache with AS entries that we
        # know don't have pushers, nor even read receipts.
        local_users_in_room = set(
            u
            for u in users_in_room
            if self.hs.is_mine_id(u)
            and not self.get_if_app_services_interested_in_user(u)
        )

        # users in the room who have pushers need to get push rules run because
        # that's how their pushers work
        if_users_with_pushers = yield self.get_if_users_have_pushers(
            local_users_in_room, on_invalidate=cache_context.invalidate
        )
        user_ids = set(
            uid for uid, have_pusher in if_users_with_pushers.items() if have_pusher
        )

        users_with_receipts = yield self.get_users_with_read_receipts_in_room(
            room_id, on_invalidate=cache_context.invalidate
        )

        # any users with pushers must be ours: they have pushers
        for uid in users_with_receipts:
            if uid in local_users_in_room:
                user_ids.add(uid)

        rules_by_user = yield self.bulk_get_push_rules(
            user_ids, on_invalidate=cache_context.invalidate
        )

        rules_by_user = {k: v for k, v in rules_by_user.items() if v is not None}

        defer.returnValue(rules_by_user)

    @cachedList(
        cached_method_name="get_push_rules_enabled_for_user",
        list_name="user_ids",
        num_args=1,
        inlineCallbacks=True,
    )
    def bulk_get_push_rules_enabled(self, user_ids):
        if not user_ids:
            defer.returnValue({})

        results = {user_id: {} for user_id in user_ids}

        rows = yield self._simple_select_many_batch(
            table="push_rules_enable",
            column="user_name",
            iterable=user_ids,
            retcols=("user_name", "rule_id", "enabled"),
            desc="bulk_get_push_rules_enabled",
        )
        for row in rows:
            enabled = bool(row['enabled'])
            results.setdefault(row['user_name'], {})[row['rule_id']] = enabled
        defer.returnValue(results)


class PushRuleStore(PushRulesWorkerStore):
    @defer.inlineCallbacks
    def add_push_rule(
        self,
        user_id,
        rule_id,
        priority_class,
        conditions,
        actions,
        before=None,
        after=None,
    ):
        conditions_json = json.dumps(conditions)
        actions_json = json.dumps(actions)
        with self._push_rules_stream_id_gen.get_next() as ids:
            stream_id, event_stream_ordering = ids
            if before or after:
                yield self.runInteraction(
                    "_add_push_rule_relative_txn",
                    self._add_push_rule_relative_txn,
                    stream_id,
                    event_stream_ordering,
                    user_id,
                    rule_id,
                    priority_class,
                    conditions_json,
                    actions_json,
                    before,
                    after,
                )
            else:
                yield self.runInteraction(
                    "_add_push_rule_highest_priority_txn",
                    self._add_push_rule_highest_priority_txn,
                    stream_id,
                    event_stream_ordering,
                    user_id,
                    rule_id,
                    priority_class,
                    conditions_json,
                    actions_json,
                )

    def _add_push_rule_relative_txn(
        self,
        txn,
        stream_id,
        event_stream_ordering,
        user_id,
        rule_id,
        priority_class,
        conditions_json,
        actions_json,
        before,
        after,
    ):
        # Lock the table since otherwise we'll have annoying races between the
        # SELECT here and the UPSERT below.
        self.database_engine.lock_table(txn, "push_rules")

        relative_to_rule = before or after

        res = self._simple_select_one_txn(
            txn,
            table="push_rules",
            keyvalues={"user_name": user_id, "rule_id": relative_to_rule},
            retcols=["priority_class", "priority"],
            allow_none=True,
        )

        if not res:
            raise RuleNotFoundException(
                "before/after rule not found: %s" % (relative_to_rule,)
            )

        base_priority_class = res["priority_class"]
        base_rule_priority = res["priority"]

        if base_priority_class != priority_class:
            raise InconsistentRuleException(
                "Given priority class does not match class of relative rule"
            )

        if before:
            # Higher priority rules are executed first, So adding a rule before
            # a rule means giving it a higher priority than that rule.
            new_rule_priority = base_rule_priority + 1
        else:
            # We increment the priority of the existing rules to make space for
            # the new rule. Therefore if we want this rule to appear after
            # an existing rule we give it the priority of the existing rule,
            # and then increment the priority of the existing rule.
            new_rule_priority = base_rule_priority

        sql = (
            "UPDATE push_rules SET priority = priority + 1"
            " WHERE user_name = ? AND priority_class = ? AND priority >= ?"
        )

        txn.execute(sql, (user_id, priority_class, new_rule_priority))

        self._upsert_push_rule_txn(
            txn,
            stream_id,
            event_stream_ordering,
            user_id,
            rule_id,
            priority_class,
            new_rule_priority,
            conditions_json,
            actions_json,
        )

    def _add_push_rule_highest_priority_txn(
        self,
        txn,
        stream_id,
        event_stream_ordering,
        user_id,
        rule_id,
        priority_class,
        conditions_json,
        actions_json,
    ):
        # Lock the table since otherwise we'll have annoying races between the
        # SELECT here and the UPSERT below.
        self.database_engine.lock_table(txn, "push_rules")

        # find the highest priority rule in that class
        sql = (
            "SELECT COUNT(*), MAX(priority) FROM push_rules"
            " WHERE user_name = ? and priority_class = ?"
        )
        txn.execute(sql, (user_id, priority_class))
        res = txn.fetchall()
        (how_many, highest_prio) = res[0]

        new_prio = 0
        if how_many > 0:
            new_prio = highest_prio + 1

        self._upsert_push_rule_txn(
            txn,
            stream_id,
            event_stream_ordering,
            user_id,
            rule_id,
            priority_class,
            new_prio,
            conditions_json,
            actions_json,
        )

    def _upsert_push_rule_txn(
        self,
        txn,
        stream_id,
        event_stream_ordering,
        user_id,
        rule_id,
        priority_class,
        priority,
        conditions_json,
        actions_json,
        update_stream=True,
    ):
        """Specialised version of _simple_upsert_txn that picks a push_rule_id
        using the _push_rule_id_gen if it needs to insert the rule. It assumes
        that the "push_rules" table is locked"""

        sql = (
            "UPDATE push_rules"
            " SET priority_class = ?, priority = ?, conditions = ?, actions = ?"
            " WHERE user_name = ? AND rule_id = ?"
        )

        txn.execute(
            sql,
            (priority_class, priority, conditions_json, actions_json, user_id, rule_id),
        )

        if txn.rowcount == 0:
            # We didn't update a row with the given rule_id so insert one
            push_rule_id = self._push_rule_id_gen.get_next()

            self._simple_insert_txn(
                txn,
                table="push_rules",
                values={
                    "id": push_rule_id,
                    "user_name": user_id,
                    "rule_id": rule_id,
                    "priority_class": priority_class,
                    "priority": priority,
                    "conditions": conditions_json,
                    "actions": actions_json,
                },
            )

        if update_stream:
            self._insert_push_rules_update_txn(
                txn,
                stream_id,
                event_stream_ordering,
                user_id,
                rule_id,
                op="ADD",
                data={
                    "priority_class": priority_class,
                    "priority": priority,
                    "conditions": conditions_json,
                    "actions": actions_json,
                },
            )

    @defer.inlineCallbacks
    def delete_push_rule(self, user_id, rule_id):
        """
        Delete a push rule. Args specify the row to be deleted and can be
        any of the columns in the push_rule table, but below are the
        standard ones

        Args:
            user_id (str): The matrix ID of the push rule owner
            rule_id (str): The rule_id of the rule to be deleted
        """

        def delete_push_rule_txn(txn, stream_id, event_stream_ordering):
            self._simple_delete_one_txn(
                txn, "push_rules", {'user_name': user_id, 'rule_id': rule_id}
            )

            self._insert_push_rules_update_txn(
                txn, stream_id, event_stream_ordering, user_id, rule_id, op="DELETE"
            )

        with self._push_rules_stream_id_gen.get_next() as ids:
            stream_id, event_stream_ordering = ids
            yield self.runInteraction(
                "delete_push_rule",
                delete_push_rule_txn,
                stream_id,
                event_stream_ordering,
            )

    @defer.inlineCallbacks
    def set_push_rule_enabled(self, user_id, rule_id, enabled):
        with self._push_rules_stream_id_gen.get_next() as ids:
            stream_id, event_stream_ordering = ids
            yield self.runInteraction(
                "_set_push_rule_enabled_txn",
                self._set_push_rule_enabled_txn,
                stream_id,
                event_stream_ordering,
                user_id,
                rule_id,
                enabled,
            )

    def _set_push_rule_enabled_txn(
        self, txn, stream_id, event_stream_ordering, user_id, rule_id, enabled
    ):
        new_id = self._push_rules_enable_id_gen.get_next()
        self._simple_upsert_txn(
            txn,
            "push_rules_enable",
            {'user_name': user_id, 'rule_id': rule_id},
            {'enabled': 1 if enabled else 0},
            {'id': new_id},
        )

        self._insert_push_rules_update_txn(
            txn,
            stream_id,
            event_stream_ordering,
            user_id,
            rule_id,
            op="ENABLE" if enabled else "DISABLE",
        )

    @defer.inlineCallbacks
    def set_push_rule_actions(self, user_id, rule_id, actions, is_default_rule):
        actions_json = json.dumps(actions)

        def set_push_rule_actions_txn(txn, stream_id, event_stream_ordering):
            if is_default_rule:
                # Add a dummy rule to the rules table with the user specified
                # actions.
                priority_class = -1
                priority = 1
                self._upsert_push_rule_txn(
                    txn,
                    stream_id,
                    event_stream_ordering,
                    user_id,
                    rule_id,
                    priority_class,
                    priority,
                    "[]",
                    actions_json,
                    update_stream=False,
                )
            else:
                self._simple_update_one_txn(
                    txn,
                    "push_rules",
                    {'user_name': user_id, 'rule_id': rule_id},
                    {'actions': actions_json},
                )

            self._insert_push_rules_update_txn(
                txn,
                stream_id,
                event_stream_ordering,
                user_id,
                rule_id,
                op="ACTIONS",
                data={"actions": actions_json},
            )

        with self._push_rules_stream_id_gen.get_next() as ids:
            stream_id, event_stream_ordering = ids
            yield self.runInteraction(
                "set_push_rule_actions",
                set_push_rule_actions_txn,
                stream_id,
                event_stream_ordering,
            )

    def _insert_push_rules_update_txn(
        self, txn, stream_id, event_stream_ordering, user_id, rule_id, op, data=None
    ):
        values = {
            "stream_id": stream_id,
            "event_stream_ordering": event_stream_ordering,
            "user_id": user_id,
            "rule_id": rule_id,
            "op": op,
        }
        if data is not None:
            values.update(data)

        self._simple_insert_txn(txn, "push_rules_stream", values=values)

        txn.call_after(self.get_push_rules_for_user.invalidate, (user_id,))
        txn.call_after(self.get_push_rules_enabled_for_user.invalidate, (user_id,))
        txn.call_after(
            self.push_rules_stream_cache.entity_has_changed, user_id, stream_id
        )

    def get_all_push_rule_updates(self, last_id, current_id, limit):
        """Get all the push rules changes that have happend on the server"""
        if last_id == current_id:
            return defer.succeed([])

        def get_all_push_rule_updates_txn(txn):
            sql = (
                "SELECT stream_id, event_stream_ordering, user_id, rule_id,"
                " op, priority_class, priority, conditions, actions"
                " FROM push_rules_stream"
                " WHERE ? < stream_id AND stream_id <= ?"
                " ORDER BY stream_id ASC LIMIT ?"
            )
            txn.execute(sql, (last_id, current_id, limit))
            return txn.fetchall()

        return self.runInteraction(
            "get_all_push_rule_updates", get_all_push_rule_updates_txn
        )

    def get_push_rules_stream_token(self):
        """Get the position of the push rules stream.
        Returns a pair of a stream id for the push_rules stream and the
        room stream ordering it corresponds to."""
        return self._push_rules_stream_id_gen.get_current_token()

    def get_max_push_rules_stream_id(self):
        return self.get_push_rules_stream_token()[0]


class RuleNotFoundException(Exception):
    pass


class InconsistentRuleException(Exception):
    pass
