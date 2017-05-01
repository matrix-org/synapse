from twisted.internet import defer
from autobahn.twisted.websocket import WebSocketServerProtocol, \
    WebSocketServerFactory
from autobahn.websocket.util import create_url
from synapse.api.errors import AuthError, Codes
from synapse.api.filtering import FilterCollection, DEFAULT_FILTER_COLLECTION
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

        # echo back message verbatim
        self.sendMessage(payload, isBinary)

    def onClose(self, wasClean, code, reason):
        logger.info("WebSocket connection closed: {0} {1}".format(code, reason))
        if self.currentSync is not None:
            self.currentSync.cancel()

    def startSyncingClient(self):
        logger.info("Started syncing for %s." % self.peer)
        self.shouldSync = True
        self._sync()

    def _sync(self):
        sync_handler = self.factory.hs.get_sync_handler()
        request_key = (
            self.user['user'],
            SYNC_TIMEOUT,
            None if self.since is None else self.since.to_string(),
            None,
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
            self._process_sync_events(result)
            self.currentSync = self._sync()
            logger.debug("Returning from _handle_sync")
            return
            # Sync again

    def _process_sync_events(self, result):
        time_now = self.factory.hs.get_clock().time_msec()

        joined = SyncRestServlet.encode_joined(
            result.joined, time_now, self.user['token_id'],
            self.filter.event_fields
        )

        invited = SyncRestServlet.encode_invited(
            result.invited, time_now, self.user['token_id']
        )

        archived = SyncRestServlet.encode_archived(
            result.archived, time_now, self.user['token_id'],
            self.filter.event_fields,
        )

        response_content = {
            "account_data": {"events": result.account_data},
            "to_device": {"events": result.to_device},
            "device_lists": {
                "changed": list(result.device_lists),
            },
            "presence": SyncRestServlet.encode_presence(
                result.presence, time_now
            ),
            "rooms": {
                "join": joined,
                "invite": invited,
                "leave": archived,
            },
            "next_batch": result.next_batch.to_string(),
        }
        self.sendMessage(json.dumps(response_content))

class SynapseWebsocketFactory(WebSocketServerFactory):
    def __init__(self, address, hs):
        ws_address = create_url(address[0], port=address[1], isSecure=False)
        super(SynapseWebsocketFactory, self).__init__(ws_address)
        self.protocol = SynapseWebsocketProtocol
        self.hs = hs
        self.clients = []
