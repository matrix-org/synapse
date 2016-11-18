from ._base import client_v2_patterns
from twisted.internet import defer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.api.errors import AuthError, SynapseError, StoreError, Codes
import logging

class AggregationRestServlet(RestServlet):

    PATTERNS = client_v2_patterns("/room/(?P<room_id>[^/]+)/aggregation$")

    def __init__(self, hs):
        super(AggregationRestServlet, self).__init__()
        self.auth = hs.get_auth()
        self.sync_handler = hs.get_sync_handler()
        self.clock = hs.get_clock()
        self.filtering = hs.get_filtering()
        self.presence_handler = hs.get_presence_handler()
        self.aggregation_handler = hs.get_handlers().aggregation_handler

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request, allow_guest=False)
        yield self.handler.get_aggregations(room_id)

    @defer.inlineCallbacks
    def on_POST(self, request, room_id):
        '''
        Available Special (Interpolated values) are: $user $target $self
            $user - the message author
            $target - event specified by target_id: <event_id> in the message
            $self - the message body

        Example Post Body:
            {
                'aggregation_field_names': ['emoticon'],
                'aggregation_event_name': 'm.room.experimental.emoticon',
                'aggregation_type': 'append',
                'aggregation_event_schema': {
                    'type': 'object',
                    'emoticon': { 'type': 'string' }
                    required: ['emoticon']
                },
                'constraints': [],
            }
        '''
        requester = yield self.auth.get_user_by_req(request, allow_guest=False)

        aggregation_spec = register_json = parse_json_object_from_request(request)

        is_room_creator = yield self.aggregation_handler.is_room_creator(requester.user, room_id)

        if not is_room_creator:
            raise AuthError(403, 'Only Room Creator Can Modify Aggregations')

        if not self.aggregation_handler.validate(aggregation_spec):
           raise SynapseError(400, 'Invalid Aggregation Event Spec')

        self.aggregation_handler.upsert_aggregation(room_id, aggregation_spec)
        defer.returnValue((200, {}))

def register_servlets(hs, http_server):
    AggregationRestServlet(hs).register(http_server)
