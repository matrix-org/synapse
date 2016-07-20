import synapse.handlers
import synapse.handlers.auth
import synapse.handlers.device
import synapse.storage
import synapse.state

class HomeServer(object):
    def get_auth_handler(self) -> synapse.handlers.auth.AuthHandler:
        pass

    def get_datastore(self) -> synapse.storage.DataStore:
        pass

    def get_device_handler(self) -> synapse.handlers.device.DeviceHandler:
        pass

    def get_handlers(self) -> synapse.handlers.Handlers:
        pass

    def get_state_handler(self) -> synapse.state.StateHandler:
        pass
