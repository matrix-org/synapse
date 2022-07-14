# Copyright 2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
# Copyright 2019,2020 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
from typing import (
    TYPE_CHECKING,
    Any,
    Collection,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
)

from synapse.api import errors
from synapse.api.constants import EduTypes, EventTypes
from synapse.api.errors import (
    Codes,
    FederationDeniedError,
    HttpResponseException,
    RequestSendFailed,
    SynapseError,
)
from synapse.logging.opentracing import log_kv, set_tag, trace
from synapse.metrics.background_process_metrics import (
    run_as_background_process,
    wrap_as_background_process,
)
from synapse.types import (
    JsonDict,
    StreamKeyType,
    StreamToken,
    UserID,
    get_domain_from_id,
    get_verify_key_from_cross_signing_key,
)
from synapse.util import stringutils
from synapse.util.async_helpers import Linearizer
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.metrics import measure_func
from synapse.util.retryutils import NotRetryingDestination

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

MAX_DEVICE_DISPLAY_NAME_LEN = 100
DELETE_STALE_DEVICES_INTERVAL_MS = 24 * 60 * 60 * 1000


class DeviceWorkerHandler:
    def __init__(self, hs: "HomeServer"):
        self.clock = hs.get_clock()
        self.hs = hs
        self.store = hs.get_datastores().main
        self.notifier = hs.get_notifier()
        self.state = hs.get_state_handler()
        self._state_storage = hs.get_storage_controllers().state
        self._auth_handler = hs.get_auth_handler()
        self.server_name = hs.hostname

    @trace
    async def get_devices_by_user(self, user_id: str) -> List[JsonDict]:
        """
        Retrieve the given user's devices

        Args:
            user_id: The user ID to query for devices.
        Returns:
            info on each device
        """

        set_tag("user_id", user_id)
        device_map = await self.store.get_devices_by_user(user_id)

        ips = await self.store.get_last_client_ip_by_device(user_id, device_id=None)

        devices = list(device_map.values())
        for device in devices:
            _update_device_from_client_ips(device, ips)

        log_kv(device_map)
        return devices

    @trace
    async def get_device(self, user_id: str, device_id: str) -> JsonDict:
        """Retrieve the given device

        Args:
            user_id: The user to get the device from
            device_id: The device to fetch.

        Returns:
            info on the device
        Raises:
            errors.NotFoundError: if the device was not found
        """
        device = await self.store.get_device(user_id, device_id)
        if device is None:
            raise errors.NotFoundError()

        ips = await self.store.get_last_client_ip_by_device(user_id, device_id)
        _update_device_from_client_ips(device, ips)

        set_tag("device", device)
        set_tag("ips", ips)

        return device

    async def get_device_changes_in_shared_rooms(
        self, user_id: str, room_ids: Collection[str], from_token: StreamToken
    ) -> Collection[str]:
        """Get the set of users whose devices have changed who share a room with
        the given user.
        """
        changed_users = await self.store.get_device_list_changes_in_rooms(
            room_ids, from_token.device_list_key
        )

        if changed_users is not None:
            # We also check if the given user has changed their device. If
            # they're in no rooms then the above query won't include them.
            changed = await self.store.get_users_whose_devices_changed(
                from_token.device_list_key, [user_id]
            )
            changed_users.update(changed)
            return changed_users

        # If the DB returned None then the `from_token` is too old, so we fall
        # back on looking for device updates for all users.

        users_who_share_room = await self.store.get_users_who_share_room_with_user(
            user_id
        )

        tracked_users = set(users_who_share_room)

        # Always tell the user about their own devices
        tracked_users.add(user_id)

        changed = await self.store.get_users_whose_devices_changed(
            from_token.device_list_key, tracked_users
        )

        return changed

    @trace
    @measure_func("device.get_user_ids_changed")
    async def get_user_ids_changed(
        self, user_id: str, from_token: StreamToken
    ) -> JsonDict:
        """Get list of users that have had the devices updated, or have newly
        joined a room, that `user_id` may be interested in.
        """

        set_tag("user_id", user_id)
        set_tag("from_token", from_token)
        now_room_key = self.store.get_room_max_token()

        room_ids = await self.store.get_rooms_for_user(user_id)

        changed = await self.get_device_changes_in_shared_rooms(
            user_id, room_ids, from_token
        )

        # Then work out if any users have since joined
        rooms_changed = self.store.get_rooms_that_changed(room_ids, from_token.room_key)

        member_events = await self.store.get_membership_changes_for_user(
            user_id, from_token.room_key, now_room_key
        )
        rooms_changed.update(event.room_id for event in member_events)

        stream_ordering = from_token.room_key.stream

        possibly_changed = set(changed)
        possibly_left = set()
        for room_id in rooms_changed:
            current_state_ids = await self._state_storage.get_current_state_ids(room_id)

            # The user may have left the room
            # TODO: Check if they actually did or if we were just invited.
            if room_id not in room_ids:
                for etype, state_key in current_state_ids.keys():
                    if etype != EventTypes.Member:
                        continue
                    possibly_left.add(state_key)
                continue

            # Fetch the current state at the time.
            try:
                event_ids = await self.store.get_forward_extremities_for_room_at_stream_ordering(
                    room_id, stream_ordering=stream_ordering
                )
            except errors.StoreError:
                # we have purged the stream_ordering index since the stream
                # ordering: treat it the same as a new room
                event_ids = []

            # special-case for an empty prev state: include all members
            # in the changed list
            if not event_ids:
                log_kv(
                    {"event": "encountered empty previous state", "room_id": room_id}
                )
                for etype, state_key in current_state_ids.keys():
                    if etype != EventTypes.Member:
                        continue
                    possibly_changed.add(state_key)
                continue

            current_member_id = current_state_ids.get((EventTypes.Member, user_id))
            if not current_member_id:
                continue

            # mapping from event_id -> state_dict
            prev_state_ids = await self._state_storage.get_state_ids_for_events(
                event_ids
            )

            # Check if we've joined the room? If so we just blindly add all the users to
            # the "possibly changed" users.
            for state_dict in prev_state_ids.values():
                member_event = state_dict.get((EventTypes.Member, user_id), None)
                if not member_event or member_event != current_member_id:
                    for etype, state_key in current_state_ids.keys():
                        if etype != EventTypes.Member:
                            continue
                        possibly_changed.add(state_key)
                    break

            # If there has been any change in membership, include them in the
            # possibly changed list. We'll check if they are joined below,
            # and we're not toooo worried about spuriously adding users.
            for key, event_id in current_state_ids.items():
                etype, state_key = key
                if etype != EventTypes.Member:
                    continue

                # check if this member has changed since any of the extremities
                # at the stream_ordering, and add them to the list if so.
                for state_dict in prev_state_ids.values():
                    prev_event_id = state_dict.get(key, None)
                    if not prev_event_id or prev_event_id != event_id:
                        if state_key != user_id:
                            possibly_changed.add(state_key)
                        break

        if possibly_changed or possibly_left:
            possibly_joined = possibly_changed
            possibly_left = possibly_changed | possibly_left

            # Double check if we still share rooms with the given user.
            users_rooms = await self.store.get_rooms_for_users_with_stream_ordering(
                possibly_left
            )
            for changed_user_id, entries in users_rooms.items():
                if any(e.room_id in room_ids for e in entries):
                    possibly_left.discard(changed_user_id)
                else:
                    possibly_joined.discard(changed_user_id)

        else:
            possibly_joined = set()
            possibly_left = set()

        result = {"changed": list(possibly_joined), "left": list(possibly_left)}

        log_kv(result)

        return result

    async def on_federation_query_user_devices(self, user_id: str) -> JsonDict:
        stream_id, devices = await self.store.get_e2e_device_keys_for_federation_query(
            user_id
        )
        master_key = await self.store.get_e2e_cross_signing_key(user_id, "master")
        self_signing_key = await self.store.get_e2e_cross_signing_key(
            user_id, "self_signing"
        )

        return {
            "user_id": user_id,
            "stream_id": stream_id,
            "devices": devices,
            "master_key": master_key,
            "self_signing_key": self_signing_key,
        }


class DeviceHandler(DeviceWorkerHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.federation_sender = hs.get_federation_sender()

        self.device_list_updater = DeviceListUpdater(hs, self)

        federation_registry = hs.get_federation_registry()

        federation_registry.register_edu_handler(
            EduTypes.DEVICE_LIST_UPDATE,
            self.device_list_updater.incoming_device_list_update,
        )

        hs.get_distributor().observe("user_left_room", self.user_left_room)

        # Whether `_handle_new_device_update_async` is currently processing.
        self._handle_new_device_update_is_processing = False

        # If a new device update may have happened while the loop was
        # processing.
        self._handle_new_device_update_new_data = False

        # On start up check if there are any updates pending.
        hs.get_reactor().callWhenRunning(self._handle_new_device_update_async)

        self._delete_stale_devices_after = hs.config.server.delete_stale_devices_after

        # Ideally we would run this on a worker and condition this on the
        # "run_background_tasks_on" setting, but this would mean making the notification
        # of device list changes over federation work on workers, which is nontrivial.
        if self._delete_stale_devices_after is not None:
            self.clock.looping_call(
                run_as_background_process,
                DELETE_STALE_DEVICES_INTERVAL_MS,
                "delete_stale_devices",
                self._delete_stale_devices,
            )

    def _check_device_name_length(self, name: Optional[str]) -> None:
        """
        Checks whether a device name is longer than the maximum allowed length.

        Args:
            name: The name of the device.

        Raises:
            SynapseError: if the device name is too long.
        """
        if name and len(name) > MAX_DEVICE_DISPLAY_NAME_LEN:
            raise SynapseError(
                400,
                "Device display name is too long (max %i)"
                % (MAX_DEVICE_DISPLAY_NAME_LEN,),
                errcode=Codes.TOO_LARGE,
            )

    async def check_device_registered(
        self,
        user_id: str,
        device_id: Optional[str],
        initial_device_display_name: Optional[str] = None,
        auth_provider_id: Optional[str] = None,
        auth_provider_session_id: Optional[str] = None,
    ) -> str:
        """
        If the given device has not been registered, register it with the
        supplied display name.

        If no device_id is supplied, we make one up.

        Args:
            user_id:  @user:id
            device_id: device id supplied by client
            initial_device_display_name: device display name from client
            auth_provider_id: The SSO IdP the user used, if any.
            auth_provider_session_id: The session ID (sid) got from the SSO IdP.
        Returns:
            device id (generated if none was supplied)
        """

        self._check_device_name_length(initial_device_display_name)

        if device_id is not None:
            new_device = await self.store.store_device(
                user_id=user_id,
                device_id=device_id,
                initial_device_display_name=initial_device_display_name,
                auth_provider_id=auth_provider_id,
                auth_provider_session_id=auth_provider_session_id,
            )
            if new_device:
                await self.notify_device_update(user_id, [device_id])
            return device_id

        # if the device id is not specified, we'll autogen one, but loop a few
        # times in case of a clash.
        attempts = 0
        while attempts < 5:
            new_device_id = stringutils.random_string(10).upper()
            new_device = await self.store.store_device(
                user_id=user_id,
                device_id=new_device_id,
                initial_device_display_name=initial_device_display_name,
                auth_provider_id=auth_provider_id,
                auth_provider_session_id=auth_provider_session_id,
            )
            if new_device:
                await self.notify_device_update(user_id, [new_device_id])
                return new_device_id
            attempts += 1

        raise errors.StoreError(500, "Couldn't generate a device ID.")

    async def _delete_stale_devices(self) -> None:
        """Background task that deletes devices which haven't been accessed for more than
        a configured time period.
        """
        # We should only be running this job if the config option is defined.
        assert self._delete_stale_devices_after is not None
        now_ms = self.clock.time_msec()
        since_ms = now_ms - self._delete_stale_devices_after
        devices = await self.store.get_local_devices_not_accessed_since(since_ms)

        for user_id, user_devices in devices.items():
            await self.delete_devices(user_id, user_devices)

    @trace
    async def delete_all_devices_for_user(
        self, user_id: str, except_device_id: Optional[str] = None
    ) -> None:
        """Delete all of the user's devices

        Args:
            user_id: The user to remove all devices from
            except_device_id: optional device id which should not be deleted
        """
        device_map = await self.store.get_devices_by_user(user_id)
        device_ids = list(device_map)
        if except_device_id is not None:
            device_ids = [d for d in device_ids if d != except_device_id]
        await self.delete_devices(user_id, device_ids)

    async def delete_devices(self, user_id: str, device_ids: List[str]) -> None:
        """Delete several devices

        Args:
            user_id: The user to delete devices from.
            device_ids: The list of device IDs to delete
        """

        try:
            await self.store.delete_devices(user_id, device_ids)
        except errors.StoreError as e:
            if e.code == 404:
                # no match
                set_tag("error", True)
                set_tag("reason", "User doesn't have that device id.")
            else:
                raise

        # Delete access tokens and e2e keys for each device. Not optimised as it is not
        # considered as part of a critical path.
        for device_id in device_ids:
            await self._auth_handler.delete_access_tokens_for_user(
                user_id, device_id=device_id
            )
            await self.store.delete_e2e_keys_by_device(
                user_id=user_id, device_id=device_id
            )

        await self.notify_device_update(user_id, device_ids)

    async def update_device(self, user_id: str, device_id: str, content: dict) -> None:
        """Update the given device

        Args:
            user_id: The user to update devices of.
            device_id: The device to update.
            content: body of update request
        """

        # Reject a new displayname which is too long.
        new_display_name = content.get("display_name")

        self._check_device_name_length(new_display_name)

        try:
            await self.store.update_device(
                user_id, device_id, new_display_name=new_display_name
            )
            await self.notify_device_update(user_id, [device_id])
        except errors.StoreError as e:
            if e.code == 404:
                raise errors.NotFoundError()
            else:
                raise

    @trace
    @measure_func("notify_device_update")
    async def notify_device_update(
        self, user_id: str, device_ids: Collection[str]
    ) -> None:
        """Notify that a user's device(s) has changed. Pokes the notifier, and
        remote servers if the user is local.

        Args:
            user_id: The Matrix ID of the user who's device list has been updated.
            device_ids: The device IDs that have changed.
        """
        if not device_ids:
            # No changes to notify about, so this is a no-op.
            return

        room_ids = await self.store.get_rooms_for_user(user_id)

        position = await self.store.add_device_change_to_streams(
            user_id,
            device_ids,
            room_ids=room_ids,
        )

        if not position:
            # This should only happen if there are no updates, so we bail.
            return

        for device_id in device_ids:
            logger.debug(
                "Notifying about update %r/%r, ID: %r", user_id, device_id, position
            )

        # specify the user ID too since the user should always get their own device list
        # updates, even if they aren't in any rooms.
        self.notifier.on_new_event(
            StreamKeyType.DEVICE_LIST, position, users={user_id}, rooms=room_ids
        )

        # We may need to do some processing asynchronously for local user IDs.
        if self.hs.is_mine_id(user_id):
            self._handle_new_device_update_async()

    async def notify_user_signature_update(
        self, from_user_id: str, user_ids: List[str]
    ) -> None:
        """Notify a user that they have made new signatures of other users.

        Args:
            from_user_id: the user who made the signature
            user_ids: the users IDs that have new signatures
        """

        position = await self.store.add_user_signature_change_to_streams(
            from_user_id, user_ids
        )

        self.notifier.on_new_event(
            StreamKeyType.DEVICE_LIST, position, users=[from_user_id]
        )

    async def user_left_room(self, user: UserID, room_id: str) -> None:
        user_id = user.to_string()
        room_ids = await self.store.get_rooms_for_user(user_id)
        if not room_ids:
            # We no longer share rooms with this user, so we'll no longer
            # receive device updates. Mark this in DB.
            await self.store.mark_remote_user_device_list_as_unsubscribed(user_id)

    async def store_dehydrated_device(
        self,
        user_id: str,
        device_data: JsonDict,
        initial_device_display_name: Optional[str] = None,
    ) -> str:
        """Store a dehydrated device for a user.  If the user had a previous
        dehydrated device, it is removed.

        Args:
            user_id: the user that we are storing the device for
            device_data: the dehydrated device information
            initial_device_display_name: The display name to use for the device
        Returns:
            device id of the dehydrated device
        """
        device_id = await self.check_device_registered(
            user_id,
            None,
            initial_device_display_name,
        )
        old_device_id = await self.store.store_dehydrated_device(
            user_id, device_id, device_data
        )
        if old_device_id is not None:
            await self.delete_devices(user_id, [old_device_id])
        return device_id

    async def get_dehydrated_device(
        self, user_id: str
    ) -> Optional[Tuple[str, JsonDict]]:
        """Retrieve the information for a dehydrated device.

        Args:
            user_id: the user whose dehydrated device we are looking for
        Returns:
            a tuple whose first item is the device ID, and the second item is
            the dehydrated device information
        """
        return await self.store.get_dehydrated_device(user_id)

    async def rehydrate_device(
        self, user_id: str, access_token: str, device_id: str
    ) -> dict:
        """Process a rehydration request from the user.

        Args:
            user_id: the user who is rehydrating the device
            access_token: the access token used for the request
            device_id: the ID of the device that will be rehydrated
        Returns:
            a dict containing {"success": True}
        """
        success = await self.store.remove_dehydrated_device(user_id, device_id)

        if not success:
            raise errors.NotFoundError()

        # If the dehydrated device was successfully deleted (the device ID
        # matched the stored dehydrated device), then modify the access
        # token to use the dehydrated device's ID and copy the old device
        # display name to the dehydrated device, and destroy the old device
        # ID
        old_device_id = await self.store.set_device_for_access_token(
            access_token, device_id
        )
        old_device = await self.store.get_device(user_id, old_device_id)
        if old_device is None:
            raise errors.NotFoundError()
        await self.store.update_device(user_id, device_id, old_device["display_name"])
        # can't call self.delete_device because that will clobber the
        # access token so call the storage layer directly
        await self.store.delete_devices(user_id, [old_device_id])
        await self.store.delete_e2e_keys_by_device(
            user_id=user_id, device_id=old_device_id
        )

        # tell everyone that the old device is gone and that the dehydrated
        # device has a new display name
        await self.notify_device_update(user_id, [old_device_id, device_id])

        return {"success": True}

    @wrap_as_background_process("_handle_new_device_update_async")
    async def _handle_new_device_update_async(self) -> None:
        """Called when we have a new local device list update that we need to
        send out over federation.

        This happens in the background so as not to block the original request
        that generated the device update.
        """
        if self._handle_new_device_update_is_processing:
            self._handle_new_device_update_new_data = True
            return

        self._handle_new_device_update_is_processing = True

        # The stream ID we processed previous iteration (if any), and the set of
        # hosts we've already poked about for this update. This is so that we
        # don't poke the same remote server about the same update repeatedly.
        current_stream_id = None
        hosts_already_sent_to: Set[str] = set()

        try:
            while True:
                self._handle_new_device_update_new_data = False
                rows = await self.store.get_uncoverted_outbound_room_pokes()
                if not rows:
                    # If the DB returned nothing then there is nothing left to
                    # do, *unless* a new device list update happened during the
                    # DB query.
                    if self._handle_new_device_update_new_data:
                        continue
                    else:
                        return

                for user_id, device_id, room_id, stream_id, opentracing_context in rows:
                    hosts = set()

                    # Ignore any users that aren't ours
                    if self.hs.is_mine_id(user_id):
                        joined_user_ids = await self.store.get_users_in_room(room_id)
                        hosts = {get_domain_from_id(u) for u in joined_user_ids}
                        hosts.discard(self.server_name)

                    # Check if we've already sent this update to some hosts
                    if current_stream_id == stream_id:
                        hosts -= hosts_already_sent_to

                    await self.store.add_device_list_outbound_pokes(
                        user_id=user_id,
                        device_id=device_id,
                        room_id=room_id,
                        stream_id=stream_id,
                        hosts=hosts,
                        context=opentracing_context,
                    )

                    # Notify replication that we've updated the device list stream.
                    self.notifier.notify_replication()

                    if hosts:
                        logger.info(
                            "Sending device list update notif for %r to: %r",
                            user_id,
                            hosts,
                        )
                        for host in hosts:
                            self.federation_sender.send_device_messages(
                                host, immediate=False
                            )
                            # TODO: when called, this isn't in a logging context.
                            # This leads to log spam, sentry event spam, and massive
                            # memory usage.
                            # See https://github.com/matrix-org/synapse/issues/12552.
                            # log_kv(
                            #     {"message": "sent device update to host", "host": host}
                            # )

                    if current_stream_id != stream_id:
                        # Clear the set of hosts we've already sent to as we're
                        # processing a new update.
                        hosts_already_sent_to.clear()

                    hosts_already_sent_to.update(hosts)
                    current_stream_id = stream_id

        finally:
            self._handle_new_device_update_is_processing = False


def _update_device_from_client_ips(
    device: JsonDict, client_ips: Mapping[Tuple[str, str], Mapping[str, Any]]
) -> None:
    ip = client_ips.get((device["user_id"], device["device_id"]), {})
    device.update({"last_seen_ts": ip.get("last_seen"), "last_seen_ip": ip.get("ip")})


class DeviceListUpdater:
    "Handles incoming device list updates from federation and updates the DB"

    def __init__(self, hs: "HomeServer", device_handler: DeviceHandler):
        self.store = hs.get_datastores().main
        self.federation = hs.get_federation_client()
        self.clock = hs.get_clock()
        self.device_handler = device_handler

        self._remote_edu_linearizer = Linearizer(name="remote_device_list")

        # user_id -> list of updates waiting to be handled.
        self._pending_updates: Dict[
            str, List[Tuple[str, str, Iterable[str], JsonDict]]
        ] = {}

        # Recently seen stream ids. We don't bother keeping these in the DB,
        # but they're useful to have them about to reduce the number of spurious
        # resyncs.
        self._seen_updates: ExpiringCache[str, Set[str]] = ExpiringCache(
            cache_name="device_update_edu",
            clock=self.clock,
            max_len=10000,
            expiry_ms=30 * 60 * 1000,
            iterable=True,
        )

        # Attempt to resync out of sync device lists every 30s.
        self._resync_retry_in_progress = False
        self.clock.looping_call(
            run_as_background_process,
            30 * 1000,
            func=self._maybe_retry_device_resync,
            desc="_maybe_retry_device_resync",
        )

    @trace
    async def incoming_device_list_update(
        self, origin: str, edu_content: JsonDict
    ) -> None:
        """Called on incoming device list update from federation. Responsible
        for parsing the EDU and adding to pending updates list.
        """

        set_tag("origin", origin)
        set_tag("edu_content", edu_content)
        user_id = edu_content.pop("user_id")
        device_id = edu_content.pop("device_id")
        stream_id = str(edu_content.pop("stream_id"))  # They may come as ints
        prev_ids = edu_content.pop("prev_id", [])
        if not isinstance(prev_ids, list):
            raise SynapseError(
                400, "Device list update had an invalid 'prev_ids' field"
            )
        prev_ids = [str(p) for p in prev_ids]  # They may come as ints

        if get_domain_from_id(user_id) != origin:
            # TODO: Raise?
            logger.warning(
                "Got device list update edu for %r/%r from %r",
                user_id,
                device_id,
                origin,
            )

            set_tag("error", True)
            log_kv(
                {
                    "message": "Got a device list update edu from a user and "
                    "device which does not match the origin of the request.",
                    "user_id": user_id,
                    "device_id": device_id,
                }
            )
            return

        room_ids = await self.store.get_rooms_for_user(user_id)
        if not room_ids:
            # We don't share any rooms with this user. Ignore update, as we
            # probably won't get any further updates.
            set_tag("error", True)
            log_kv(
                {
                    "message": "Got an update from a user for which "
                    "we don't share any rooms",
                    "other user_id": user_id,
                }
            )
            logger.warning(
                "Got device list update edu for %r/%r, but don't share a room",
                user_id,
                device_id,
            )
            return

        logger.debug("Received device list update for %r/%r", user_id, device_id)

        self._pending_updates.setdefault(user_id, []).append(
            (device_id, stream_id, prev_ids, edu_content)
        )

        await self._handle_device_updates(user_id)

    @measure_func("_incoming_device_list_update")
    async def _handle_device_updates(self, user_id: str) -> None:
        "Actually handle pending updates."

        async with self._remote_edu_linearizer.queue(user_id):
            pending_updates = self._pending_updates.pop(user_id, [])
            if not pending_updates:
                # This can happen since we batch updates
                return

            for device_id, stream_id, prev_ids, _ in pending_updates:
                logger.debug(
                    "Handling update %r/%r, ID: %r, prev: %r ",
                    user_id,
                    device_id,
                    stream_id,
                    prev_ids,
                )

            # Given a list of updates we check if we need to resync. This
            # happens if we've missed updates.
            resync = await self._need_to_do_resync(user_id, pending_updates)

            if logger.isEnabledFor(logging.INFO):
                logger.info(
                    "Received device list update for %s, requiring resync: %s. Devices: %s",
                    user_id,
                    resync,
                    ", ".join(u[0] for u in pending_updates),
                )

            if resync:
                await self.user_device_resync(user_id)
            else:
                # Simply update the single device, since we know that is the only
                # change (because of the single prev_id matching the current cache)
                for device_id, stream_id, _, content in pending_updates:
                    await self.store.update_remote_device_list_cache_entry(
                        user_id, device_id, content, stream_id
                    )

                await self.device_handler.notify_device_update(
                    user_id, [device_id for device_id, _, _, _ in pending_updates]
                )

                self._seen_updates.setdefault(user_id, set()).update(
                    stream_id for _, stream_id, _, _ in pending_updates
                )

    async def _need_to_do_resync(
        self, user_id: str, updates: Iterable[Tuple[str, str, Iterable[str], JsonDict]]
    ) -> bool:
        """Given a list of updates for a user figure out if we need to do a full
        resync, or whether we have enough data that we can just apply the delta.
        """
        seen_updates: Set[str] = self._seen_updates.get(user_id, set())

        extremity = await self.store.get_device_list_last_stream_id_for_remote(user_id)

        logger.debug("Current extremity for %r: %r", user_id, extremity)

        stream_id_in_updates = set()  # stream_ids in updates list
        for _, stream_id, prev_ids, _ in updates:
            if not prev_ids:
                # We always do a resync if there are no previous IDs
                return True

            for prev_id in prev_ids:
                if prev_id == extremity:
                    continue
                elif prev_id in seen_updates:
                    continue
                elif prev_id in stream_id_in_updates:
                    continue
                else:
                    return True

            stream_id_in_updates.add(stream_id)

        return False

    @trace
    async def _maybe_retry_device_resync(self) -> None:
        """Retry to resync device lists that are out of sync, except if another retry is
        in progress.
        """
        if self._resync_retry_in_progress:
            return

        try:
            # Prevent another call of this function to retry resyncing device lists so
            # we don't send too many requests.
            self._resync_retry_in_progress = True
            # Get all of the users that need resyncing.
            need_resync = await self.store.get_user_ids_requiring_device_list_resync()
            # Iterate over the set of user IDs.
            for user_id in need_resync:
                try:
                    # Try to resync the current user's devices list.
                    result = await self.user_device_resync(
                        user_id=user_id,
                        mark_failed_as_stale=False,
                    )

                    # user_device_resync only returns a result if it managed to
                    # successfully resync and update the database. Updating the table
                    # of users requiring resync isn't necessary here as
                    # user_device_resync already does it (through
                    # self.store.update_remote_device_list_cache).
                    if result:
                        logger.debug(
                            "Successfully resynced the device list for %s",
                            user_id,
                        )
                except Exception as e:
                    # If there was an issue resyncing this user, e.g. if the remote
                    # server sent a malformed result, just log the error instead of
                    # aborting all the subsequent resyncs.
                    logger.debug(
                        "Could not resync the device list for %s: %s",
                        user_id,
                        e,
                    )
        finally:
            # Allow future calls to retry resyncinc out of sync device lists.
            self._resync_retry_in_progress = False

    async def user_device_resync(
        self, user_id: str, mark_failed_as_stale: bool = True
    ) -> Optional[JsonDict]:
        """Fetches all devices for a user and updates the device cache with them.

        Args:
            user_id: The user's id whose device_list will be updated.
            mark_failed_as_stale: Whether to mark the user's device list as stale
                if the attempt to resync failed.
        Returns:
            A dict with device info as under the "devices" in the result of this
            request:
            https://matrix.org/docs/spec/server_server/r0.1.2#get-matrix-federation-v1-user-devices-userid
        """
        logger.debug("Attempting to resync the device list for %s", user_id)
        log_kv({"message": "Doing resync to update device list."})
        # Fetch all devices for the user.
        origin = get_domain_from_id(user_id)
        try:
            result = await self.federation.query_user_devices(origin, user_id)
        except NotRetryingDestination:
            if mark_failed_as_stale:
                # Mark the remote user's device list as stale so we know we need to retry
                # it later.
                await self.store.mark_remote_user_device_cache_as_stale(user_id)

            return None
        except (RequestSendFailed, HttpResponseException) as e:
            logger.warning(
                "Failed to handle device list update for %s: %s",
                user_id,
                e,
            )

            if mark_failed_as_stale:
                # Mark the remote user's device list as stale so we know we need to retry
                # it later.
                await self.store.mark_remote_user_device_cache_as_stale(user_id)

            # We abort on exceptions rather than accepting the update
            # as otherwise synapse will 'forget' that its device list
            # is out of date. If we bail then we will retry the resync
            # next time we get a device list update for this user_id.
            # This makes it more likely that the device lists will
            # eventually become consistent.
            return None
        except FederationDeniedError as e:
            set_tag("error", True)
            log_kv({"reason": "FederationDeniedError"})
            logger.info(e)
            return None
        except Exception as e:
            set_tag("error", True)
            log_kv(
                {"message": "Exception raised by federation request", "exception": e}
            )
            logger.exception("Failed to handle device list update for %s", user_id)

            if mark_failed_as_stale:
                # Mark the remote user's device list as stale so we know we need to retry
                # it later.
                await self.store.mark_remote_user_device_cache_as_stale(user_id)

            return None
        log_kv({"result": result})
        stream_id = result["stream_id"]
        devices = result["devices"]

        # Get the master key and the self-signing key for this user if provided in the
        # response (None if not in the response).
        # The response will not contain the user signing key, as this key is only used by
        # its owner, thus it doesn't make sense to send it over federation.
        master_key = result.get("master_key")
        self_signing_key = result.get("self_signing_key")

        ignore_devices = False
        # If the remote server has more than ~1000 devices for this user
        # we assume that something is going horribly wrong (e.g. a bot
        # that logs in and creates a new device every time it tries to
        # send a message).  Maintaining lots of devices per user in the
        # cache can cause serious performance issues as if this request
        # takes more than 60s to complete, internal replication from the
        # inbound federation worker to the synapse master may time out
        # causing the inbound federation to fail and causing the remote
        # server to retry, causing a DoS.  So in this scenario we give
        # up on storing the total list of devices and only handle the
        # delta instead.
        if len(devices) > 1000:
            logger.warning(
                "Ignoring device list snapshot for %s as it has >1K devs (%d)",
                user_id,
                len(devices),
            )
            devices = []
            ignore_devices = True
        else:
            prev_stream_id = await self.store.get_device_list_last_stream_id_for_remote(
                user_id
            )
            cached_devices = await self.store.get_cached_devices_for_user(user_id)

            # To ensure that a user with no devices is cached, we skip the resync only
            # if we have a stream_id from previously writing a cache entry.
            if prev_stream_id is not None and cached_devices == {
                d["device_id"]: d for d in devices
            }:
                logging.info(
                    "Skipping device list resync for %s, as our cache matches already",
                    user_id,
                )
                devices = []
                ignore_devices = True

        for device in devices:
            logger.debug(
                "Handling resync update %r/%r, ID: %r",
                user_id,
                device["device_id"],
                stream_id,
            )

        if not ignore_devices:
            await self.store.update_remote_device_list_cache(
                user_id, devices, stream_id
            )
        # mark the cache as valid, whether or not we actually processed any device
        # list updates.
        await self.store.mark_remote_user_device_cache_as_valid(user_id)
        device_ids = [device["device_id"] for device in devices]

        # Handle cross-signing keys.
        cross_signing_device_ids = await self.process_cross_signing_key_update(
            user_id,
            master_key,
            self_signing_key,
        )
        device_ids = device_ids + cross_signing_device_ids

        if device_ids:
            await self.device_handler.notify_device_update(user_id, device_ids)

        # We clobber the seen updates since we've re-synced from a given
        # point.
        self._seen_updates[user_id] = {stream_id}

        return result

    async def process_cross_signing_key_update(
        self,
        user_id: str,
        master_key: Optional[JsonDict],
        self_signing_key: Optional[JsonDict],
    ) -> List[str]:
        """Process the given new master and self-signing key for the given remote user.

        Args:
            user_id: The ID of the user these keys are for.
            master_key: The dict of the cross-signing master key as returned by the
                remote server.
            self_signing_key: The dict of the cross-signing self-signing key as returned
                by the remote server.

        Return:
            The device IDs for the given keys.
        """
        device_ids = []

        current_keys_map = await self.store.get_e2e_cross_signing_keys_bulk([user_id])
        current_keys = current_keys_map.get(user_id) or {}

        if master_key and master_key != current_keys.get("master"):
            await self.store.set_e2e_cross_signing_key(user_id, "master", master_key)
            _, verify_key = get_verify_key_from_cross_signing_key(master_key)
            # verify_key is a VerifyKey from signedjson, which uses
            # .version to denote the portion of the key ID after the
            # algorithm and colon, which is the device ID
            device_ids.append(verify_key.version)
        if self_signing_key and self_signing_key != current_keys.get("self_signing"):
            await self.store.set_e2e_cross_signing_key(
                user_id, "self_signing", self_signing_key
            )
            _, verify_key = get_verify_key_from_cross_signing_key(self_signing_key)
            device_ids.append(verify_key.version)

        return device_ids
