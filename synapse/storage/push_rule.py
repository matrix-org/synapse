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

        batch_size = 100

        def f(txn, user_ids_to_fetch):
            sql = (
                "SELECT pr.*"
                " FROM push_rules AS pr"
                " LEFT JOIN push_rules_enable AS pre"
                " ON pr.user_name = pre.user_name AND pr.rule_id = pre.rule_id"
                " WHERE pr.user_name"
                " IN (" + ",".join("?" for _ in user_ids_to_fetch) + ")"
                " AND (pre.enabled IS NULL OR pre.enabled = 1)"
                " ORDER BY pr.user_name, pr.priority_class DESC, pr.priority DESC"
            )
            txn.execute(sql, user_ids_to_fetch)
            return self.cursor_to_dict(txn)

        results = {}

        chunks = [user_ids[i:i+batch_size] for i in xrange(0, len(user_ids), batch_size)]
        for batch_user_ids in chunks:
            rows = yield self.runInteraction(
                "bulk_get_push_rules", f, batch_user_ids
            )

            for row in rows:
                results.setdefault(row['user_name'], []).append(row)
        defer.returnValue(results)

    @defer.inlineCallbacks
    def add_push_rule(self, before, after, **kwargs):
        vals = kwargs
        if 'conditions' in vals:
            vals['conditions'] = json.dumps(vals['conditions'])
        if 'actions' in vals:
            vals['actions'] = json.dumps(vals['actions'])

        # we could check the rest of the keys are valid column names
        # but sqlite will do that anyway so I think it's just pointless.
        vals.pop("id", None)

        if before or after:
            ret = yield self.runInteraction(
                "_add_push_rule_relative_txn",
                self._add_push_rule_relative_txn,
                before=before,
                after=after,
                **vals
            )
            defer.returnValue(ret)
        else:
            ret = yield self.runInteraction(
                "_add_push_rule_highest_priority_txn",
                self._add_push_rule_highest_priority_txn,
                **vals
            )
            defer.returnValue(ret)

    def _add_push_rule_relative_txn(self, txn, user_id, **kwargs):
        after = kwargs.pop("after", None)
        relative_to_rule = kwargs.pop("before", after)

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

        priority_class = res["priority_class"]
        base_rule_priority = res["priority"]

        if 'priority_class' in kwargs and kwargs['priority_class'] != priority_class:
            raise InconsistentRuleException(
                "Given priority class does not match class of relative rule"
            )

        new_rule = kwargs
        new_rule.pop("before", None)
        new_rule.pop("after", None)
        new_rule['priority_class'] = priority_class
        new_rule['user_name'] = user_id
        new_rule['id'] = self._push_rule_id_gen.get_next_txn(txn)

        # check if the priority before/after is free
        new_rule_priority = base_rule_priority
        if after:
            new_rule_priority -= 1
        else:
            new_rule_priority += 1

        new_rule['priority'] = new_rule_priority

        sql = (
            "SELECT COUNT(*) FROM push_rules"
            " WHERE user_name = ? AND priority_class = ? AND priority = ?"
        )
        txn.execute(sql, (user_id, priority_class, new_rule_priority))
        res = txn.fetchall()
        num_conflicting = res[0][0]

        # if there are conflicting rules, bump everything
        if num_conflicting:
            sql = "UPDATE push_rules SET priority = priority "
            if after:
                sql += "-1"
            else:
                sql += "+1"
            sql += " WHERE user_name = ? AND priority_class = ? AND priority "
            if after:
                sql += "<= ?"
            else:
                sql += ">= ?"

            txn.execute(sql, (user_id, priority_class, new_rule_priority))

        txn.call_after(
            self.get_push_rules_for_user.invalidate, (user_id,)
        )

        txn.call_after(
            self.get_push_rules_enabled_for_user.invalidate, (user_id,)
        )

        self._simple_insert_txn(
            txn,
            table="push_rules",
            values=new_rule,
        )

    def _add_push_rule_highest_priority_txn(self, txn, user_id,
                                            priority_class, **kwargs):
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

        # and insert the new rule
        new_rule = kwargs
        new_rule['id'] = self._push_rule_id_gen.get_next_txn(txn)
        new_rule['user_name'] = user_id
        new_rule['priority_class'] = priority_class
        new_rule['priority'] = new_prio

        txn.call_after(
            self.get_push_rules_for_user.invalidate, (user_id,)
        )
        txn.call_after(
            self.get_push_rules_enabled_for_user.invalidate, (user_id,)
        )

        self._simple_insert_txn(
            txn,
            table="push_rules",
            values=new_rule,
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
