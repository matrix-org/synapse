from twisted.internet import defer

from synapse.storage import background_updates
import json

class AggregationStore(background_updates.BackgroundUpdateStore):
    def __init__(self, hs):
        super(AggregationStore, self).__init__(hs)

    @defer.inlineCallbacks
    def is_room_creator(self, user, room_id):
        result = yield self._simple_select_one_onecol(
            table="rooms",
            keyvalues={
                "creator": user.to_string(),
                "room_id": room_id
            },
            retcol="creator",
            allow_none=True,
            desc="is_room_creator",
        )
        defer.returnValue(True if result else False)

    @defer.inlineCallbacks
    def upsert_aggregation(self, room_id, aggregation_spec):
        result = yield self._simple_upsert('aggregation_tasks',
            {
                'aggregation_event_name': aggregation_spec['aggregation_event_name'],
                'room_id': room_id
            },
            {
                'aggregation_spec': json.dumps(aggregation_spec)
            },
            desc='upsert_aggregation'
        )
        defer.returnValue(result)

    @defer.inlineCallbacks
    def get_aggregation_tasks(self, room_id=None, event_name=None):
        where_params = {}
        if room_id:
            where_params['room_id'] = room_id
        if event_name:
            where_params['aggregation_event_name'] = event_name
        result = yield self._simple_select_list(
            'aggregation_tasks',
            where_params,
            ('room_id', 'aggregation_event_name', 'aggregation_spec'),
            desc="get_aggregation_for_room"
        )
        defer.returnValue(result)

    def replace_aggregate_entry(self, room_id, target_id, event_name, latest_event_id, aggregate_entry):
        sql = '''
            INSERT INTO aggregation_entries(
                room_id,
                target_id,
                event_name,
                latest_event_id,
                aggregation_data
            )
            VALUES (%s, %s, %s, %s, %s) ON CONFLICT UPDATE
        '''
        params = (
            room_id, target_id,
            event_name, latest_event_id,
            json.dumps(aggregate_entry)
        )
        return self.runInteraction(
            'replace_aggrregate_entry',
            self._simple_run_txn,
            sql, params,
        )

    @staticmethod
    def _simple_run_txn(txn, sql, params):
        return txn.execute(sql, params)

    @classmethod
    def _simple_select_txn(cls, txn, sql, params=()):
        try:
            if len(params):
                sql = sql % params
            txn.execute(sql)
        except Exception as e:
            import traceback, sys
            traceback.print_exc(file=sys.stdout)
        return cls.cursor_to_dict(txn)

    def append_aggregate_entries(self, room_id, target_id, event_name, latest_event_id, aggregate_entries):
        sql = '''
            INSERT INTO aggregation_entries(room_id, target_id, event_name, latest_event_id)
                VALUES(%s, %s, %s, %s)
                ON CONFLICT DO NOTHING;
            UPDATE aggregation_entries
                SET latest_event_id=%s,
                    aggregation_data=to_jsonb(
                        ARRAY(SELECT jsonb_array_elements_text(
                            aggregation_data
                        )) || %s::text[]
                    )
                WHERE target_id=%s
            '''
        params = (
            room_id,
            target_id,
            event_name,
            latest_event_id,
            latest_event_id,
            [json.dumps(entry) for entry in aggregate_entries],
            target_id
        )

        return self.runInteraction(
            'append_aggregate_entries',
            self._simple_run_txn,
            sql, params,
        )
