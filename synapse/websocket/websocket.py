from twisted.internet import defer
from autobahn.twisted.websocket import WebSocketServerProtocol, \
    WebSocketServerFactory
from autobahn.websocket.util import create_url
from synapse.api.errors import AuthError, Codes
from synapse.api.filtering import FilterCollection, DEFAULT_FILTER_COLLECTION
from synapse.rest.client.v2_alpha._base import set_timeline_upper_limit
from synapse.rest.client.v2_alpha.sync import SyncRestServlet
from synapse.handlers.sync import SyncConfig
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
        self.access_token = None
        self.user = None
        self.filter = DEFAULT_FILTER_COLLECTION
        self.since = None
        self.full_state = False
        self.currentSync = None
        logger.info("connecting: {0}".format(request.peer))
        try:
            access_token = request.params.get("access_token")
            access_token = access_token[0].decode('utf-8')
        except KeyError as ex:
            self.sendClose(3001, ERR_NO_AT)
            return
        auth = self.factory.hs.get_auth()
        logger.info("Checking access_token for {1}".format(access_token, request.peer))
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

        logger.info("authenticated {0} ({1}) okay".format(user['user'], request.peer))
        self.access_token = access_token
        self.user = user

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
            "ping": self._handle_ping
        }

        method = supported_methods.get(msg["method"],
            lambda empty: self.sendMessage(json.dumps({
                id: msg.id,
                errorcode: "M_BAD_JSON",
                error: "Unknown method"
            }))
        )
        logger.debug("Execute handler for type: " + msg["method"])
        method(msg)

    def onClose(self, wasClean, code, reason):
        logger.info("WebSocket connection closed: {0} {1}".format(code, reason))
        self.shouldSync = False
        if self.currentSync is not None:
            self.currentSync.cancel()

    def startSyncingClient(self):
        logger.info("Started syncing for %s." % self.peer)
        self.shouldSync = True
        self.currentSync = self._sync()

    def _sync(self):
        sync_handler = self.factory.hs.get_sync_handler()
        request_key = (
            self.user['user'],
            0, # timeout
            self.since,
            self.filter_id,
            self.full_state,
            self.user['device_id'],
        )
        sync_config = SyncConfig(
            user=self.user['user'],
            filter_collection=self.filter,
            is_guest=self.user['is_guest'],
            request_key=request_key,
            device_id=self.user['device_id'],
        )

        logger.debug("Syncing with %s" % str(self.since))
        sync = sync_handler.wait_for_sync_for_user(
            sync_config,
            since_token=self.since,
            timeout=SYNC_TIMEOUT,
            full_state=self.full_state
        )
        logger.debug(sync)
        sync.addCallback(
            lambda result: self._handle_sync(result)
        )
        logger.debug("Returning from _sync")
        return sync

    def _handle_sync(self, result):
        logger.info("Got sync")
        if self.shouldSync:
            self.since = result.next_batch
            logger.debug("Sending sync")
            time_now = self.factory.clock.time_msec()

            self.sendMessage(json.dumps(SyncRestServlet.encode_response(
                time_now,
                result,
                self.access_token,
                self.filter
            )),False)
            self.currentSync = self._sync()
            logger.debug("Returning from _handle_sync")
            return
            # Sync again

    def _handle_ping(self, msg):
            self.sendMessage(bytes('{"id":"' + msg["id"] + '","result":{}}'))

class SynapseWebsocketFactory(WebSocketServerFactory):
    def __init__(self, address, hs):
        ws_address = create_url(address[0], port=address[1], isSecure=False)
        super(SynapseWebsocketFactory, self).__init__(ws_address)
        self.protocol = SynapseWebsocketProtocol
        self.hs = hs
        self.clock = hs.get_clock()
        self.filtering = hs.get_filtering()
        self.clients = []
