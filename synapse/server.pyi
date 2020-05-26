from typing import Dict

import twisted.internet

import synapse.api.auth
import synapse.config.homeserver
import synapse.crypto.keyring
import synapse.federation.federation_server
import synapse.federation.sender
import synapse.federation.transport.client
import synapse.handlers
import synapse.handlers.auth
import synapse.handlers.deactivate_account
import synapse.handlers.device
import synapse.handlers.e2e_keys
import synapse.handlers.message
import synapse.handlers.presence
import synapse.handlers.register
import synapse.handlers.room
import synapse.handlers.room_member
import synapse.handlers.set_password
import synapse.http.client
import synapse.notifier
import synapse.push.pusherpool
import synapse.replication.tcp.client
import synapse.replication.tcp.handler
import synapse.rest.media.v1.media_repository
import synapse.server_notices.server_notices_manager
import synapse.server_notices.server_notices_sender
import synapse.state
import synapse.storage
from synapse.events.builder import EventBuilderFactory
from synapse.replication.tcp.streams import Stream

class HomeServer(object):
    @property
    def config(self) -> synapse.config.homeserver.HomeServerConfig:
        pass
    @property
    def hostname(self) -> str:
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
    def get_simple_http_client(self) -> synapse.http.client.SimpleHttpClient:
        """Fetch an HTTP client implementation which doesn't do any blacklisting
        or support any HTTP_PROXY settings"""
        pass
    def get_proxied_http_client(self) -> synapse.http.client.SimpleHttpClient:
        """Fetch an HTTP client implementation which doesn't do any blacklisting
        but does support HTTP_PROXY settings"""
        pass
    def get_deactivate_account_handler(
        self,
    ) -> synapse.handlers.deactivate_account.DeactivateAccountHandler:
        pass
    def get_room_creation_handler(self) -> synapse.handlers.room.RoomCreationHandler:
        pass
    def get_room_member_handler(self) -> synapse.handlers.room_member.RoomMemberHandler:
        pass
    def get_event_creation_handler(
        self,
    ) -> synapse.handlers.message.EventCreationHandler:
        pass
    def get_set_password_handler(
        self,
    ) -> synapse.handlers.set_password.SetPasswordHandler:
        pass
    def get_federation_sender(self) -> synapse.federation.sender.FederationSender:
        pass
    def get_federation_transport_client(
        self,
    ) -> synapse.federation.transport.client.TransportLayerClient:
        pass
    def get_media_repository_resource(
        self,
    ) -> synapse.rest.media.v1.media_repository.MediaRepositoryResource:
        pass
    def get_media_repository(
        self,
    ) -> synapse.rest.media.v1.media_repository.MediaRepository:
        pass
    def get_server_notices_manager(
        self,
    ) -> synapse.server_notices.server_notices_manager.ServerNoticesManager:
        pass
    def get_server_notices_sender(
        self,
    ) -> synapse.server_notices.server_notices_sender.ServerNoticesSender:
        pass
    def get_notifier(self) -> synapse.notifier.Notifier:
        pass
    def get_presence_handler(self) -> synapse.handlers.presence.BasePresenceHandler:
        pass
    def get_clock(self) -> synapse.util.Clock:
        pass
    def get_reactor(self) -> twisted.internet.base.ReactorBase:
        pass
    def get_keyring(self) -> synapse.crypto.keyring.Keyring:
        pass
    def get_tcp_replication(
        self,
    ) -> synapse.replication.tcp.handler.ReplicationCommandHandler:
        pass
    def get_replication_data_handler(
        self,
    ) -> synapse.replication.tcp.client.ReplicationDataHandler:
        pass
    def get_federation_registry(
        self,
    ) -> synapse.federation.federation_server.FederationHandlerRegistry:
        pass
    def is_mine_id(self, domain_id: str) -> bool:
        pass
    def get_instance_id(self) -> str:
        pass
    def get_instance_name(self) -> str:
        pass
    def get_event_builder_factory(self) -> EventBuilderFactory:
        pass
    def get_storage(self) -> synapse.storage.Storage:
        pass
    def get_registration_handler(self) -> synapse.handlers.register.RegistrationHandler:
        pass
    def get_macaroon_generator(self) -> synapse.handlers.auth.MacaroonGenerator:
        pass
    def get_pusherpool(self) -> synapse.push.pusherpool.PusherPool:
        pass
    def get_replication_streams(self) -> Dict[str, Stream]:
        pass
