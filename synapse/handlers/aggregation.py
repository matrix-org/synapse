import logging
from twisted.internet import defer
from ._base import BaseHandler

import jsonschema
import re
import json
from itertools import groupby
from collections import defaultdict

logger = logging.getLogger(__name__)

AGGREGATION_TYPE = 'm.room._aggregation'
PRUNE_AGGREGATION_EVENTS = False

AGGREGATION_SCHEMA = {
    'aggregation_field_names': {
        'type' : 'array',
        'items': {
            'type': 'string'
        },
    },
    'aggregation_event_schema': {
        'type': 'object'
    },
    'aggregation_type': { 'type': 'string', 'oneOf': ['append', 'replace']},
    'constraints': {
        'type': 'array',
        'items': {
            'type': 'object',
            'op': {
                'type': 'string',
                'oneOf': ['equal', 'greaterThan', 'lessThan', 'lessThanOrEqualTo', 'greaterThanOrEqualTo', 'notEqual']
            },
            'conditions': {
                'type': 'array',
                'items': {
                    'type': 'string'
                }
            }
        }
    },
    'aggregation_event_name' : { 'type': 'string' },
    'type' : 'object',
    'required': ['aggregation_field_names', 'aggregation_event_schema', 'aggregation_type', 'aggregation_event_name']
}

class AggregationTask:
    def __init__(self, store, room_id, aggregation_spec):
        self.store = store
        self.room_id = room_id
        self.aggregation_spec = aggregation_spec
        self.constraints = aggregation_spec.get('constraints', [])
        self.aggregation_field_names = aggregation_spec['aggregation_field_names']
        self.aggregation_type = aggregation_spec['aggregation_type']
        self.aggregation_event_name = aggregation_spec['aggregation_event_name']
        self.aggregation_event_schema = aggregation_spec['aggregation_event_schema']

    def interpolate_params(params, event, target, user):
        param_literals = []
        for param in params:
            if param.startswith('$user'):
                param_literal = user
            elif param.startswith('$self'):
                param_literal = event
            elif param.startswith('$target'):
                param_literal = target
            paths = param.split('.')
            for path in paths[1:]:
                param_literal = param_literal.get(path) or param_literal.__dict__.get(path)
            param_literals.append(param_literal)
        return param_literals

    def check_aggregation_event_constraints(event, user, group):
        for constraint in self.constraints:
            param_literals = self.interpolate_params(constraint['params'], event, user, group)
            check_constraint(constraint['op'], param_literals)

    def content_for_aggregate_replace(self, group, target):
        for event in reversed(group):
            event_content = event['content']
            try:
                jsonschema.validate(
                    self.aggregation_event_schema,
                    event_content
                )
            except jsonschema.ValidationError:
                logger.warn('Invalid Schema: Skipping Aggregation for Event %s' % event['event_id'])
                continue
            aggregate_entry = { field_name : content[field_name] for field_name in self.aggregation_field_names }
            aggregate_entry['event_id'] = event['event_id']
            return aggregate_entry

    def content_for_aggregate_append(self, group, target):
        aggregate_entries = []
        for event in group:
            event_content = event['content']
            try:
                jsonschema.validate(
                    self.aggregation_event_schema,
                    event_content
                )
            except jsonschema.ValidationError:
                logger.warn('Invalid Schema: Skipping Aggregation for Event %s' % event['event_id'])
                continue
            aggregate_entry = { field_name : event_content[field_name] for field_name in self.aggregation_field_names }
            aggregate_entry['event_id'] = event['event_id']
            aggregate_entry['sender'] = event['sender']
            aggregate_entries.append(aggregate_entry)
        return aggregate_entries

    @defer.inlineCallbacks
    def run(self, events):
        def get_aggregation_event_target(event):
            # Although content is a JSON blob it's always stored as Text
            # Would be nicer to cast this with the psycopg cursor tracer than
            # here..
            content = event.get('content')
            if content and not isinstance(content, dict):
                event['content'] = content = json.loads(content)
                return content.get('target_id')
            else:
                event['content'] = {}

        event_groups = groupby(events, get_aggregation_event_target)
        backlog = []
        for (target_id, group) in event_groups:
            target_event = yield self.store.get_event(target_id, check_redacted=False, get_prev_content=False, allow_rejected=False, allow_none=True)
            if not target_event:
                # TODO backlogging
                backlog.push((target_id, group))

            if self.aggregation_type == 'replace':
                aggregate_entry = self.content_for_aggregate_replace(group, target_event)
                # Don't bother writing to DB if all entries were invalid
                if aggregate_entry:
                    self.store.replace_aggregate_entry(
                        self.room_id, target_id,
                        self.aggregation_event_name,
                        aggregate_entry['event_id'], aggregate_entry
                    )

            elif self.aggregation_type == 'append':
                aggregate_entries = self.content_for_aggregate_append(group, target_event)
                # Don't bother writing to DB if all entries were invalid
                if len(aggregate_entries):
                    latest_event_id = max(entry['event_id'] for entry in aggregate_entries)

                    self.store.append_aggregate_entries(
                        self.room_id, target_id,
                        self.aggregation_event_name,
                        latest_event_id, aggregate_entries
                    )
            # Pruning events is not atomic with updating aggregation_entries
            # But since the client will always receive some unaggregated events
            # It is up to them to check latest_event_id on the aggregation_entry
            # for a target
            if PRUNE_AGGREGATION_EVENTS:
                ids_to_prune = [event.get('stream_ordering') for event in group]
                sql = '''
                    DELETE FROM events WHERE stream_ordering is ANY(%s)
                '''
                yield self.store.runInteraction(
                    'prune_aggregation_events',
                    self._simple_run_txn,
                    sql, (ids_to_prune)
                )

class AggregationHandler(BaseHandler):
    BACKGROUND_UPDATE_INTERVAL_MS = 5000
    BACKGROUND_UPDATE_DURATION_MS = 100 # UNUSED

    def __init__(self, hs):
        super(AggregationHandler, self).__init__(hs)
        self.pending_events = defaultdict(list)
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def process_aggregation_events(self, desired_duration_ms):
        sql = '''
            SELECT MAX(latest_event_id) AS latest_event_id, event_name FROM aggregation_entries
            GROUP BY event_name;
        '''
        latest_entries = yield self.store.runInteraction(
            'get_latest_aggregation_entries',
            self.store._simple_select_txn,
            sql
        )
        # Convert to a hash for easy lookup
        latest_entries = { row['event_name'] : row['latest_event_id'] \
        for row in latest_entries }

        sql = '''
            SELECT MAX(event_id) AS event_id, type, room_id FROM events WHERE type LIKE 'm.room._aggregation%' GROUP BY type, room_id;
        '''

        latest_aggregation_events = yield self.store.runInteraction(
            'get_latest_aggregation_events',
            self.store._simple_select_txn,
            sql
        )

        needs_catchup = []
        for event in latest_aggregation_events:
            event_type = event['type']
            # Doesn't need catchup only if latest_event_id in aggregate entries
            # is the same as the event table event_id
            if not event_type in latest_entries:
                # '$0' as a floor for comparing event_id strings
                event['latest_event_id'] = '$0'
                needs_catchup.append(event)
            elif latest_entries[event_type] != event['event_id']:
                event['latest_event_id'] = latest_entries[event_type]
                needs_catchup.append(event)

        sql = '''
            SELECT * FROM events WHERE type = '%s' AND event_id > '%s'
        '''
        for entry in needs_catchup:
            params = (entry['type'], entry['latest_event_id'])

            events_for_aggregation = yield self.store.runInteraction(
                'get_events_for_aggregation',
                self.store._simple_select_txn,
                sql, params
            )


            if not len(events_for_aggregation):
                continue
            task = yield self.get_task_for_event(entry['room_id'], entry['type'])
            if not task:
                continue
            task.run(events_for_aggregation)

    def get_aggregation_key(self, event):
        if event.type.startswith('m.room._aggregation'):
            return (event.room_id, event.type)

    def is_aggregation_event(self, event):
        if event.type.startswith('m.room._aggregation'):
            return True

    # Currently unused
    def on_new_event(self, event, _context):
        aggregation_key = self.get_aggregation_key(event)
        if aggregation_key:
            self.pending_events[aggregation_key].append((event))
        # if self.is_aggregation_event(event):
        #     self.pending_events.append(event)

    @defer.inlineCallbacks
    def run_aggregation_events(self):
        while True:
            sleep = defer.Deferred()
            self._background_update_timer = self.clock.call_later(
                self.BACKGROUND_UPDATE_INTERVAL_MS / 1000., sleep.callback, None
            )
            try:
                yield sleep
            finally:
                self._background_update_timer = None

            yield self.process_aggregation_events(self.BACKGROUND_UPDATE_DURATION_MS)

    # @defer.inlineCallbacks
    # def process_aggregation_events(self, desired_duration_ms):
    #     for ((room_id, aggregation_event_name), event_group) in self.pending_events.items():
    #         task = yield self.get_task_for_event(room_id, aggregation_event_name)
    #         self.pending_events[(room_id, aggregation_event_name)] = []
    #         task.run(event_group)
    #    event = self.pending_events.pop_left()
    #    task = yield self.get_task_for_event(event.room_id, event.type)
    #    task.run(event)


    @defer.inlineCallbacks
    def get_task_for_event(self, room_id, aggregation_event_name):
        try:
            aggregation_info = (yield self.store.get_aggregation_tasks(room_id, aggregation_event_name))[0]
        except IndexError:
            logger.warn('Could not find task for (room_id, aggregation_event_type): (%s, %s)',
                room_id, aggregation_event_name)
            defer.returnValue(None)
        defer.returnValue(AggregationTask(
            self.store,
            aggregation_info['room_id'],
            aggregation_info['aggregation_spec']
        ))

    def upsert_aggregation(self, room_id, aggregation_spec):
        return self.store.upsert_aggregation(room_id, aggregation_spec)

    def validate(self, aggregation_event_spec):
        try:
            jsonschema.validate(aggregation_event_spec, AGGREGATION_SCHEMA)
            return True
        except:
            return False

    def is_room_creator(self, user, room_id):
        return self.store.is_room_creator(user, room_id)
