import synapse.api.auth
import synapse.federation.transaction_queue
import synapse.federation.transport.client
import synapse.handlers
import synapse.handlers.auth
import synapse.handlers.device
import synapse.handlers.e2e_keys
import synapse.storage
import synapse.state

class HomeServer(object):
    def get_auth(self) -> synapse.api.auth.Auth:
        pass

    def get_auth_handler(self) -> synapse.handlers.auth.AuthHandler:
        pass

    def get_datastore(self) -> synapse.storage.DataStore:
        pass

    def get_device_handler(self) -> synapse.handlers.device.DeviceHandler:
        pass

    def get_e2e_keys_handler(self) -> synapse.handlers.e2e_keys.E2eKeysHandler:
        pass

    def get_handlers(self) -> synapse.handlers.Handlers:
        pass

    def get_state_handler(self) -> synapse.state.StateHandler:
        pass

    def get_federation_sender(self) -> synapse.federation.transaction_queue.TransactionQueue:
        pass

    def get_federation_transport_client(self) -> synapse.federation.transport.client.TransportLayerClient:
        pass
