import synapse.api.auth
import synapse.config.homeserver
import synapse.federation.sender
import synapse.federation.transaction_queue
import synapse.federation.transport.client
import synapse.handlers
import synapse.handlers.auth
import synapse.handlers.deactivate_account
import synapse.handlers.device
import synapse.handlers.e2e_keys
import synapse.handlers.message
import synapse.handlers.room
import synapse.handlers.room_member
import synapse.handlers.set_password
import synapse.rest.media.v1.media_repository
import synapse.server_notices.server_notices_manager
import synapse.server_notices.server_notices_sender
import synapse.state
import synapse.storage

class HomeServer(object):
    @property
    def config(self) -> synapse.config.homeserver.HomeServerConfig:
        pass
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
    def get_state_resolution_handler(self) -> synapse.state.StateResolutionHandler:
        pass
    def get_deactivate_account_handler(
        self
    ) -> synapse.handlers.deactivate_account.DeactivateAccountHandler:
        pass
    def get_room_creation_handler(self) -> synapse.handlers.room.RoomCreationHandler:
        pass
    def get_room_member_handler(self) -> synapse.handlers.room_member.RoomMemberHandler:
        pass
    def get_event_creation_handler(
        self
    ) -> synapse.handlers.message.EventCreationHandler:
        pass
    def get_set_password_handler(
        self
    ) -> synapse.handlers.set_password.SetPasswordHandler:
        pass
    def get_federation_sender(self) -> synapse.federation.sender.FederationSender:
        pass
    def get_federation_transport_client(
        self
    ) -> synapse.federation.transport.client.TransportLayerClient:
        pass
    def get_media_repository_resource(
        self
    ) -> synapse.rest.media.v1.media_repository.MediaRepositoryResource:
        pass
    def get_media_repository(
        self
    ) -> synapse.rest.media.v1.media_repository.MediaRepository:
        pass
    def get_server_notices_manager(
        self
    ) -> synapse.server_notices.server_notices_manager.ServerNoticesManager:
        pass
    def get_server_notices_sender(
        self
    ) -> synapse.server_notices.server_notices_sender.ServerNoticesSender:
        pass
