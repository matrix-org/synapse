from twisted.internet import defer
from autobahn.twisted.websocket import WebSocketServerProtocol, \
    WebSocketServerFactory
from autobahn.websocket.util import create_url
from synapse.api.errors import AuthError, Codes
from synapse.api.filtering import FilterCollection, DEFAULT_FILTER_COLLECTION
from synapse.rest.client.v2_alpha._base import set_timeline_upper_limit
from synapse.rest.client.v2_alpha.sync import SyncRestServlet
from synapse.handlers.sync import SyncConfig
from synapse.types import StreamToken, create_requester
import logging
import json
logger = logging.getLogger("synapse.websocket")

# Close Reason Codes:
# 3001 - No Access Token
# 3002 - Unknown Access Token
# 3003 - Generic failure trying to auth.

ERR_NO_AT = unicode("No access_token provided.")
ERR_UNKNOWN_AT = unicode("Unknown access_token.")
ERR_UNKNOWN_FAIL = unicode("Unknown failure trying to auth.")
SYNC_TIMEOUT = 90000


class SynapseWebsocketProtocol(WebSocketServerProtocol):
    @defer.inlineCallbacks
    def onConnect(self, request):
        self.filter = DEFAULT_FILTER_COLLECTION
        self.since = None
        self.full_state = False
        self.currentSync = None
        logger.info("connecting: {0}".format(request.peer))

        logger.info("Checking access_token for {0}".format(request.peer))
        access_token = request.params.get("access_token", None)
        if access_token is None:
            self.sendClose(3001, ERR_NO_AT)
            return
        access_token = access_token[0].decode('utf-8')

        user = None
        auth = self.factory.hs.get_auth()
        try:
            user = yield auth.get_user_by_access_token(access_token)
        except AuthError as ex:
            self.sendClose(3002, ERR_UNKNOWN_AT)
            logger.info("Closing due to auth error %s" % ex)
            return
        except Exception as ex:
            self.sendClose(3003, ERR_UNKNOWN_FAIL)
            logger.info("Closing due to unknown error %s" % ex)
            return

        try:
            self.requester = create_requester(
                    user["user"],
                    user["token_id"],
                    user["is_guest"],
                    user.get("device_id"),
                    app_service=None
            )
        except Exception as ex:
            logger.warn("Requester got not be generated")
            self.sendClose(3003, ERR_UNKNOWN_FAIL)

        since = request.params.get("since", None)
        if since is not None:
            since = since[0].decode('utf-8')
            self.since = StreamToken.from_string(since)

        filter_id = request.params.get("filter", None)
        if filter_id[0]:
            if filter_id[0].startswith('{'):
                try:
                    filter_object = json.loads(filter_id[0])
                    set_timeline_upper_limit(filter_object,
                        self.factory.hs.config.filter_timeline_limit)
                except:
                    raise SynapseError(400, "Invalid filter JSON")
                self.factory.filtering.check_valid_filter(filter_object)
                self.filter = FilterCollection(filter_object)
            else:
                self.filter = yield self.factory.filtering.get_user_filter(
                    user['user'].localpart, filter_id[0]
                )
            self.filter_id = filter_id[0]

        defer.returnValue(("m.json"))

    def onOpen(self):
        logger.info("New connection.")
        self.shouldSync = False
        self.startSyncingClient()

    @defer.inlineCallbacks
    def onMessage(self, payload, isBinary):
        if isBinary:
            logger.info("Binary message received: {0} bytes".format(len(payload)))
            return  # Ignore binary for now, but perhaps support something like BSON in the future.
        else:
            logger.info("Text message received: {0}".format(payload.decode('utf8')))

        msg = {}
        try:
            msg = json.loads(payload.decode('utf8'))
        except Exception as ex:
            logger.warn("Received payload is not json")
            return

        supported_methods = {
            "ping":         self._handle_ping,
            "read_markers": self._handle_read_markers,
            "send":         self._handle_send,
            "typing":       self._handle_typing,
        }

        response = None
        method = supported_methods.get(msg["method"],
            lambda msg: json.dumps({
                "id": msg["id"],
                "errorcode": "M_BAD_JSON",
                "error": "Unknown method"
            })
        )
        result = yield method(msg)
        self.sendMessage(result)

    def onClose(self, wasClean, code, reason):
        logger.info("WebSocket connection closed: {0} {1}".format(code, reason))
        self.shouldSync = False
        if self.currentSync is not None:
            self.currentSync.cancel()

    def startSyncingClient(self):
        logger.info("Started syncing for %s." % self.peer)
        self.shouldSync = True
        self.currentSync = self._sync(initial=True)

    def _sync(self, initial=False):
        sync_handler = self.factory.hs.get_sync_handler()
        request_key = (
            self.requester.user,
            0, # timeout
            self.since,
            self.filter_id,
            self.full_state,
            self.requester.device_id,
        )
        sync_config = SyncConfig(
            user=self.requester.user,
            filter_collection=self.filter,
            is_guest=self.requester.is_guest,
            request_key=request_key,
            device_id=self.requester.device_id,
        )

        logger.debug("Syncing with %s" % str(self.since))
        sync = sync_handler.wait_for_sync_for_user(
            sync_config,
            since_token=self.since,
            timeout=0 if initial else SYNC_TIMEOUT,
            full_state=self.full_state
        )
        logger.debug(sync)
        sync.addCallback(
            lambda result: self._sync_callback(result)
        )
        logger.debug("Returning from _sync")
        return sync

    def _sync_callback(self, result):
        logger.info("Got sync")
        if self.shouldSync:
            self.since = result.next_batch
            logger.debug("Sending sync")
            time_now = self.factory.clock.time_msec()

            self.sendMessage(json.dumps(SyncRestServlet.encode_response(
                time_now,
                result,
                self.requester.access_token_id,
                self.filter
            )),False)
            self.currentSync = self._sync()
            logger.debug("Returning from _sync_callback")
            return
            # Sync again

    @defer.inlineCallbacks
    def _handle_ping(self, msg):
        yield logger.debug("Execute _handle_ping")
        defer.returnValue(bytes('{"id":"' + msg["id"] + '","result":{}}'))

    @defer.inlineCallbacks
    def _handle_read_markers(self, msg):
        yield logger.debug("Execute _handle_read_markers")

        yield self.factory.presence_handler.bump_presence_active_time(self.requester.user)

        params = msg["params"]

        read_event_id = params.get("m.read", None)
        if read_event_id:
            yield self.factory.receipts_handler.received_client_receipt(
                params["room_id"],
                "m.read",
                user_id=self.requester.user.to_string(),
                event_id=read_event_id
            )

        read_marker_event_id = params.get("m.fully_read", None)
        if read_marker_event_id:
            yield self.factory.read_marker_handler.received_client_read_marker(
                params["room_id"],
                user_id=self.requester.user.to_string(),
                event_id=read_marker_event_id
            )

        defer.returnValue(bytes('{"id":"' + msg["id"] + '","result":{}}'))

    @defer.inlineCallbacks
    def _handle_send(self, msg):
        logger.debug("Execute _handle_send")
        params = msg["params"]

        event = yield self.factory.handlers.message_handler.create_and_send_nonmember_event(
            self.requester,
            {
                "type": params["event_type"],
                "content": params["content"],
                "room_id": params["room_id"],
                "sender": self.requester.user.to_string(),
            },
            txn_id=msg["id"],
        )

        defer.returnValue(json.dumps({
            "id": msg["id"],
            "result":{
                "event_id": event.event_id
            }
        }))

    @defer.inlineCallbacks
    def _handle_state(self, msg):
        logger.debug("Execute _handle_state")
        params = msg["params"]

        event_dict = {
                "type": params["event_type"],
                "content": params["content"],
                "room_id": params["room_id"],
                "sender": self.requester.user.to_string(),
        }
        if params["state_key"] is not None:
		 event_dict["state_key"] = params["state_key"]

        if params["event_type"] == EventTypes.Member:
            membership = params["content"].get("membership", None)
            event = yield self.handlers.room_member_handler.update_membership(
                self.requester,
                target=UserID.from_string(params["state_key"]),
                room_id=params["room_id"],
                action=membership,
                content=params["content"],
            )
        else:
            msg_handler = self.handlers.message_handler
            event, context = yield msg_handler.create_event(
                self.requester,
                event_dict,
                token_id=self.requester.token_id,
                txn_id=msg["id"],
            )

            yield msg_handler.send_nonmember_event(self.requester, event, context)

        ret = {"id": msg["id"]}
        if event:
            ret["result"] = {"event_id": event.event_id}
        else:
            ret["error"] = {}

        defer.returnValue(json.dumps(ret))

    @defer.inlineCallbacks
    def _handle_typing(self, msg):
        logger.info("Execute _handle_typing")
	    params = msg["params"]

        # Limit timeout to stop people from setting silly typing timeouts.
        timeout = min(params.get("timeout", 30000), 120000)

        self.factory.presence_handler.bump_presence_active_time(self.requester.user)

        if params["typing"]:
            yield self.factory.typing_handler.started_typing(
                target_user=self.requester.user,
                auth_user=self.requester.user,
                room_id=params["room_id"],
                timeout=timeout,
            )
        else:
            yield self.factory.typing_handler.stopped_typing(
                target_user=self.requester.user,
                auth_user=self.requester.user,
                room_id=params["room_id"],
            )

        defer.returnValue(bytes('{"id":"' + msg["id"] + '","result":{}}'))

class SynapseWebsocketFactory(WebSocketServerFactory):
    def __init__(self, address, hs):
        ws_address = create_url(address[0], port=address[1], isSecure=False)
        super(SynapseWebsocketFactory, self).__init__(ws_address)
        self.protocol = SynapseWebsocketProtocol
        self.hs = hs
        self.clock = hs.get_clock()
        self.filtering = hs.get_filtering()
        self.handlers = hs.get_handlers()
        self.presence_handler = hs.get_presence_handler()
        self.receipts_handler = hs.get_receipts_handler()
        self.read_marker_handler = hs.get_read_marker_handler()
        self.typing_handler = hs.get_typing_handler()
        self.clients = []
