# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from ._base import SQLBaseStore
from synapse.util.caches.descriptors import cachedInlineCallbacks
from twisted.internet import defer

import logging
import simplejson as json

logger = logging.getLogger(__name__)


class PushRuleStore(SQLBaseStore):
    @cachedInlineCallbacks()
    def get_push_rules_for_user(self, user_id):
        rows = yield self._simple_select_list(
            table="push_rules",
            keyvalues={
                "user_name": user_id,
            },
            retcols=(
                "user_name", "rule_id", "priority_class", "priority",
                "conditions", "actions",
            ),
            desc="get_push_rules_enabled_for_user",
        )

        rows.sort(
            key=lambda row: (-int(row["priority_class"]), -int(row["priority"]))
        )

        defer.returnValue(rows)

    @cachedInlineCallbacks()
    def get_push_rules_enabled_for_user(self, user_id):
        results = yield self._simple_select_list(
            table="push_rules_enable",
            keyvalues={
                'user_name': user_id
            },
            retcols=(
                "user_name", "rule_id", "enabled",
            ),
            desc="get_push_rules_enabled_for_user",
        )
        defer.returnValue({
            r['rule_id']: False if r['enabled'] == 0 else True for r in results
        })

    @defer.inlineCallbacks
    def bulk_get_push_rules(self, user_ids):
        if not user_ids:
            defer.returnValue({})

        results = {}

        rows = yield self._simple_select_many_batch(
            table="push_rules",
            column="user_name",
            iterable=user_ids,
            retcols=("*",),
            desc="bulk_get_push_rules",
        )

        rows.sort(key=lambda e: (-e["priority_class"], -e["priority"]))

        for row in rows:
            results.setdefault(row['user_name'], []).append(row)
        defer.returnValue(results)

    @defer.inlineCallbacks
    def bulk_get_push_rules_enabled(self, user_ids):
        if not user_ids:
            defer.returnValue({})

        results = {}

        rows = yield self._simple_select_many_batch(
            table="push_rules_enable",
            column="user_name",
            iterable=user_ids,
            retcols=("user_name", "rule_id", "enabled",),
            desc="bulk_get_push_rules_enabled",
        )
        for row in rows:
            results.setdefault(row['user_name'], {})[row['rule_id']] = row['enabled']
        defer.returnValue(results)

    def add_push_rule(
        self, user_id, rule_id, priority_class, conditions, actions,
        before=None, after=None
    ):
        conditions_json = json.dumps(conditions)
        actions_json = json.dumps(actions)

        if before or after:
            return self.runInteraction(
                "_add_push_rule_relative_txn",
                self._add_push_rule_relative_txn,
                user_id, rule_id, priority_class,
                conditions_json, actions_json, before, after,
            )
        else:
            return self.runInteraction(
                "_add_push_rule_highest_priority_txn",
                self._add_push_rule_highest_priority_txn,
                user_id, rule_id, priority_class,
                conditions_json, actions_json,
            )

    def _add_push_rule_relative_txn(
        self, txn, user_id, rule_id, priority_class,
        conditions_json, actions_json, before, after
    ):
        # Lock the table since otherwise we'll have annoying races between the
        # SELECT here and the UPSERT below.
        self.database_engine.lock_table(txn, "push_rules")

        relative_to_rule = before or after

        res = self._simple_select_one_txn(
            txn,
            table="push_rules",
            keyvalues={
                "user_name": user_id,
                "rule_id": relative_to_rule,
            },
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
            txn, user_id, rule_id, priority_class, new_rule_priority,
            conditions_json, actions_json,
        )

    def _add_push_rule_highest_priority_txn(
        self, txn, user_id, rule_id, priority_class,
        conditions_json, actions_json
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
            user_id, rule_id, priority_class, new_prio,
            conditions_json, actions_json,
        )

    def _upsert_push_rule_txn(
        self, txn, user_id, rule_id, priority_class,
        priority, conditions_json, actions_json
    ):
        """Specialised version of _simple_upsert_txn that picks a push_rule_id
        using the _push_rule_id_gen if it needs to insert the rule. It assumes
        that the "push_rules" table is locked"""

        sql = (
            "UPDATE push_rules"
            " SET priority_class = ?, priority = ?, conditions = ?, actions = ?"
            " WHERE user_name = ? AND rule_id = ?"
        )

        txn.execute(sql, (
            priority_class, priority, conditions_json, actions_json,
            user_id, rule_id,
        ))

        if txn.rowcount == 0:
            # We didn't update a row with the given rule_id so insert one
            push_rule_id = self._push_rule_id_gen.get_next_txn(txn)

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

        txn.call_after(
            self.get_push_rules_for_user.invalidate, (user_id,)
        )
        txn.call_after(
            self.get_push_rules_enabled_for_user.invalidate, (user_id,)
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
        yield self._simple_delete_one(
            "push_rules",
            {'user_name': user_id, 'rule_id': rule_id},
            desc="delete_push_rule",
        )

        self.get_push_rules_for_user.invalidate((user_id,))
        self.get_push_rules_enabled_for_user.invalidate((user_id,))

    @defer.inlineCallbacks
    def set_push_rule_enabled(self, user_id, rule_id, enabled):
        ret = yield self.runInteraction(
            "_set_push_rule_enabled_txn",
            self._set_push_rule_enabled_txn,
            user_id, rule_id, enabled
        )
        defer.returnValue(ret)

    def _set_push_rule_enabled_txn(self, txn, user_id, rule_id, enabled):
        new_id = self._push_rules_enable_id_gen.get_next_txn(txn)
        self._simple_upsert_txn(
            txn,
            "push_rules_enable",
            {'user_name': user_id, 'rule_id': rule_id},
            {'enabled': 1 if enabled else 0},
            {'id': new_id},
        )
        txn.call_after(
            self.get_push_rules_for_user.invalidate, (user_id,)
        )
        txn.call_after(
            self.get_push_rules_enabled_for_user.invalidate, (user_id,)
        )


class RuleNotFoundException(Exception):
    pass


class InconsistentRuleException(Exception):
    pass
