# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

import collections

from ._base import SQLBaseStore, Table
from twisted.internet import defer

import logging
import copy
import simplejson as json

logger = logging.getLogger(__name__)


class PushRuleStore(SQLBaseStore):
    @defer.inlineCallbacks
    def get_push_rules_for_user_name(self, user_name):
        sql = (
            "SELECT "+",".join(PushRuleTable.fields)+" "
            "FROM "+PushRuleTable.table_name+" "
            "WHERE user_name = ? "
            "ORDER BY priority_class DESC, priority DESC"
        )
        rows = yield self._execute(None, sql, user_name)

        dicts = []
        for r in rows:
            d = {}
            for i, f in enumerate(PushRuleTable.fields):
                d[f] = r[i]
            dicts.append(d)

        defer.returnValue(dicts)

    @defer.inlineCallbacks
    def add_push_rule(self, before, after, **kwargs):
        vals = copy.copy(kwargs)
        if 'conditions' in vals:
            vals['conditions'] = json.dumps(vals['conditions'])
        if 'actions' in vals:
            vals['actions'] = json.dumps(vals['actions'])
        # we could check the rest of the keys are valid column names
        # but sqlite will do that anyway so I think it's just pointless.
        if 'id' in vals:
            del vals['id']

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

    def _add_push_rule_relative_txn(self, txn, user_name, **kwargs):
        after = None
        relative_to_rule = None
        if 'after' in kwargs and kwargs['after']:
            after = kwargs['after']
            relative_to_rule = after
        if 'before' in kwargs and kwargs['before']:
            relative_to_rule = kwargs['before']

        # get the priority of the rule we're inserting after/before
        sql = (
            "SELECT priority_class, priority FROM ? "
            "WHERE user_name = ? and rule_id = ?" % (PushRuleTable.table_name,)
        )
        txn.execute(sql, (user_name, relative_to_rule))
        res = txn.fetchall()
        if not res:
            raise RuleNotFoundException(
                "before/after rule not found: %s" % (relative_to_rule,)
            )
        priority_class, base_rule_priority = res[0]

        if 'priority_class' in kwargs and kwargs['priority_class'] != priority_class:
            raise InconsistentRuleException(
                "Given priority class does not match class of relative rule"
            )

        new_rule = copy.copy(kwargs)
        if 'before' in new_rule:
            del new_rule['before']
        if 'after' in new_rule:
            del new_rule['after']
        new_rule['priority_class'] = priority_class
        new_rule['user_name'] = user_name

        # check if the priority before/after is free
        new_rule_priority = base_rule_priority
        if after:
            new_rule_priority -= 1
        else:
            new_rule_priority += 1

        new_rule['priority'] = new_rule_priority

        sql = (
            "SELECT COUNT(*) FROM " + PushRuleTable.table_name +
            " WHERE user_name = ? AND priority_class = ? AND priority = ?"
        )
        txn.execute(sql, (user_name, priority_class, new_rule_priority))
        res = txn.fetchall()
        num_conflicting = res[0][0]

        # if there are conflicting rules, bump everything
        if num_conflicting:
            sql = "UPDATE "+PushRuleTable.table_name+" SET priority = priority "
            if after:
                sql += "-1"
            else:
                sql += "+1"
            sql += " WHERE user_name = ? AND priority_class = ? AND priority "
            if after:
                sql += "<= ?"
            else:
                sql += ">= ?"

            txn.execute(sql, (user_name, priority_class, new_rule_priority))

        # now insert the new rule
        sql = "INSERT OR REPLACE INTO "+PushRuleTable.table_name+" ("
        sql += ",".join(new_rule.keys())+") VALUES ("
        sql += ", ".join(["?" for _ in new_rule.keys()])+")"

        txn.execute(sql, new_rule.values())

    def _add_push_rule_highest_priority_txn(self, txn, user_name,
                                            priority_class, **kwargs):
        # find the highest priority rule in that class
        sql = (
            "SELECT COUNT(*), MAX(priority) FROM " + PushRuleTable.table_name +
            " WHERE user_name = ? and priority_class = ?"
        )
        txn.execute(sql, (user_name, priority_class))
        res = txn.fetchall()
        (how_many, highest_prio) = res[0]

        new_prio = 0
        if how_many > 0:
            new_prio = highest_prio + 1

        # and insert the new rule
        new_rule = copy.copy(kwargs)
        if 'id' in new_rule:
            del new_rule['id']
        new_rule['user_name'] = user_name
        new_rule['priority_class'] = priority_class
        new_rule['priority'] = new_prio

        sql = "INSERT OR REPLACE INTO "+PushRuleTable.table_name+" ("
        sql += ",".join(new_rule.keys())+") VALUES ("
        sql += ", ".join(["?" for _ in new_rule.keys()])+")"

        txn.execute(sql, new_rule.values())

    @defer.inlineCallbacks
    def delete_push_rule(self, user_name, rule_id):
        """
        Delete a push rule. Args specify the row to be deleted and can be
        any of the columns in the push_rule table, but below are the
        standard ones

        Args:
            user_name (str): The matrix ID of the push rule owner
            rule_id (str): The rule_id of the rule to be deleted
        """
        yield self._simple_delete_one(
            PushRuleTable.table_name,
            {'user_name': user_name, 'rule_id': rule_id}
        )


class RuleNotFoundException(Exception):
    pass


class InconsistentRuleException(Exception):
    pass


class PushRuleTable(Table):
    table_name = "push_rules"

    fields = [
        "id",
        "user_name",
        "rule_id",
        "priority_class",
        "priority",
        "conditions",
        "actions",
    ]

    EntryType = collections.namedtuple("PushRuleEntry", fields)
