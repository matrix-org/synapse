# Copyright 2015, 2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Collection, Dict, Iterable, List, Optional, Union

from prometheus_client import Counter

from twisted.internet import defer

import synapse
from synapse.api.constants import EduTypes, EventTypes
from synapse.appservice import ApplicationService
from synapse.events import EventBase
from synapse.handlers.presence import format_user_presence_state
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.metrics import (
    event_processing_loop_counter,
    event_processing_loop_room_count,
)
from synapse.metrics.background_process_metrics import (
    run_as_background_process,
    wrap_as_background_process,
)
from synapse.storage.databases.main.directory import RoomAliasMapping
from synapse.types import (
    DeviceListUpdates,
    JsonDict,
    RoomAlias,
    RoomStreamToken,
    StreamKeyType,
    UserID,
)
from synapse.util.async_helpers import Linearizer
from synapse.util.metrics import Measure

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

events_processed_counter = Counter("synapse_handlers_appservice_events_processed", "")


class ApplicationServicesHandler:
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.is_mine_id = hs.is_mine_id
        self.appservice_api = hs.get_application_service_api()
        self.scheduler = hs.get_application_service_scheduler()
        self.started_scheduler = False
        self.clock = hs.get_clock()
        self.notify_appservices = hs.config.worker.should_notify_appservices
        self.event_sources = hs.get_event_sources()
        self._msc2409_to_device_messages_enabled = (
            hs.config.experimental.msc2409_to_device_messages_enabled
        )
        self._msc3202_transaction_extensions_enabled = (
            hs.config.experimental.msc3202_transaction_extensions
        )

        self.current_max = 0
        self.is_processing = False

        self._ephemeral_events_linearizer = Linearizer(
            name="appservice_ephemeral_events"
        )

    def notify_interested_services(self, max_token: RoomStreamToken) -> None:
        """Notifies (pushes) all application services interested in this event.

        Pushing is done asynchronously, so this method won't block for any
        prolonged length of time.
        """
        # We just use the minimum stream ordering and ignore the vector clock
        # component. This is safe to do as long as we *always* ignore the vector
        # clock components.
        current_id = max_token.stream

        services = self.store.get_app_services()
        if not services or not self.notify_appservices:
            return

        self.current_max = max(self.current_max, current_id)
        if self.is_processing:
            return

        # We only start a new background process if necessary rather than
        # optimistically (to cut down on overhead).
        self._notify_interested_services(max_token)

    @wrap_as_background_process("notify_interested_services")
    async def _notify_interested_services(self, max_token: RoomStreamToken) -> None:
        with Measure(self.clock, "notify_interested_services"):
            self.is_processing = True
            try:
                limit = 100
                upper_bound = -1
                while upper_bound < self.current_max:
                    (
                        upper_bound,
                        events,
                    ) = await self.store.get_new_events_for_appservice(
                        self.current_max, limit
                    )

                    events_by_room: Dict[str, List[EventBase]] = {}
                    for event in events:
                        events_by_room.setdefault(event.room_id, []).append(event)

                    async def handle_event(event: EventBase) -> None:
                        # Gather interested services
                        services = await self._get_services_for_event(event)
                        if len(services) == 0:
                            return  # no services need notifying

                        # Do we know this user exists? If not, poke the user
                        # query API for all services which match that user regex.
                        # This needs to block as these user queries need to be
                        # made BEFORE pushing the event.
                        await self._check_user_exists(event.sender)
                        if event.type == EventTypes.Member:
                            await self._check_user_exists(event.state_key)

                        if not self.started_scheduler:

                            async def start_scheduler() -> None:
                                try:
                                    await self.scheduler.start()
                                except Exception:
                                    logger.error("Application Services Failure")

                            run_as_background_process("as_scheduler", start_scheduler)
                            self.started_scheduler = True

                        # Fork off pushes to these services
                        for service in services:
                            self.scheduler.enqueue_for_appservice(
                                service, events=[event]
                            )

                        now = self.clock.time_msec()
                        ts = await self.store.get_received_ts(event.event_id)
                        assert ts is not None

                        synapse.metrics.event_processing_lag_by_event.labels(
                            "appservice_sender"
                        ).observe((now - ts) / 1000)

                    async def handle_room_events(events: Iterable[EventBase]) -> None:
                        for event in events:
                            await handle_event(event)

                    await make_deferred_yieldable(
                        defer.gatherResults(
                            [
                                run_in_background(handle_room_events, evs)
                                for evs in events_by_room.values()
                            ],
                            consumeErrors=True,
                        )
                    )

                    await self.store.set_appservice_last_pos(upper_bound)

                    synapse.metrics.event_processing_positions.labels(
                        "appservice_sender"
                    ).set(upper_bound)

                    events_processed_counter.inc(len(events))

                    event_processing_loop_room_count.labels("appservice_sender").inc(
                        len(events_by_room)
                    )

                    event_processing_loop_counter.labels("appservice_sender").inc()

                    if events:
                        now = self.clock.time_msec()
                        ts = await self.store.get_received_ts(events[-1].event_id)
                        assert ts is not None

                        synapse.metrics.event_processing_lag.labels(
                            "appservice_sender"
                        ).set(now - ts)
                        synapse.metrics.event_processing_last_ts.labels(
                            "appservice_sender"
                        ).set(ts)
            finally:
                self.is_processing = False

    def notify_interested_services_ephemeral(
        self,
        stream_key: str,
        new_token: Union[int, RoomStreamToken],
        users: Collection[Union[str, UserID]],
    ) -> None:
        """
        This is called by the notifier in the background when an ephemeral event is handled
        by the homeserver.

        This will determine which appservices are interested in the event, and submit them.

        Args:
            stream_key: The stream the event came from.

                `stream_key` can be StreamKeyType.TYPING, StreamKeyType.RECEIPT, StreamKeyType.PRESENCE,
                StreamKeyType.TO_DEVICE or StreamKeyType.DEVICE_LIST. Any other value for `stream_key`
                will cause this function to return early.

                Ephemeral events will only be pushed to appservices that have opted into
                receiving them by setting `push_ephemeral` to true in their registration
                file. Note that while MSC2409 is experimental, this option is called
                `de.sorunome.msc2409.push_ephemeral`.

                Appservices will only receive ephemeral events that fall within their
                registered user and room namespaces.

            new_token: The stream token of the event.
            users: The users that should be informed of the new event, if any.
        """
        if not self.notify_appservices:
            return

        # Notify appservices of updates in ephemeral event streams.
        # Only the following streams are currently supported.
        # FIXME: We should use constants for these values.
        if stream_key not in (
            StreamKeyType.TYPING,
            StreamKeyType.RECEIPT,
            StreamKeyType.PRESENCE,
            StreamKeyType.TO_DEVICE,
            StreamKeyType.DEVICE_LIST,
        ):
            return

        # Assert that new_token is an integer (and not a RoomStreamToken).
        # All of the supported streams that this function handles use an
        # integer to track progress (rather than a RoomStreamToken - a
        # vector clock implementation) as they don't support multiple
        # stream writers.
        #
        # As a result, we simply assert that new_token is an integer.
        # If we do end up needing to pass a RoomStreamToken down here
        # in the future, using RoomStreamToken.stream (the minimum stream
        # position) to convert to an ascending integer value should work.
        # Additional context: https://github.com/matrix-org/synapse/pull/11137
        assert isinstance(new_token, int)

        # Ignore to-device messages if the feature flag is not enabled
        if (
            stream_key == StreamKeyType.TO_DEVICE
            and not self._msc2409_to_device_messages_enabled
        ):
            return

        # Ignore device lists if the feature flag is not enabled
        if (
            stream_key == StreamKeyType.DEVICE_LIST
            and not self._msc3202_transaction_extensions_enabled
        ):
            return

        # Check whether there are any appservices which have registered to receive
        # ephemeral events.
        #
        # Note that whether these events are actually relevant to these appservices
        # is decided later on.
        services = self.store.get_app_services()
        services = [
            service
            for service in services
            # Different stream keys require different support booleans
            if (
                stream_key
                in (
                    StreamKeyType.TYPING,
                    StreamKeyType.RECEIPT,
                    StreamKeyType.PRESENCE,
                    StreamKeyType.TO_DEVICE,
                )
                and service.supports_ephemeral
            )
            or (
                stream_key == StreamKeyType.DEVICE_LIST
                and service.msc3202_transaction_extensions
            )
        ]
        if not services:
            # Bail out early if none of the target appservices have explicitly registered
            # to receive these ephemeral events.
            return

        # We only start a new background process if necessary rather than
        # optimistically (to cut down on overhead).
        self._notify_interested_services_ephemeral(
            services, stream_key, new_token, users
        )

    @wrap_as_background_process("notify_interested_services_ephemeral")
    async def _notify_interested_services_ephemeral(
        self,
        services: List[ApplicationService],
        stream_key: str,
        new_token: int,
        users: Collection[Union[str, UserID]],
    ) -> None:
        logger.debug("Checking interested services for %s", stream_key)
        with Measure(self.clock, "notify_interested_services_ephemeral"):
            for service in services:
                if stream_key == StreamKeyType.TYPING:
                    # Note that we don't persist the token (via set_appservice_stream_type_pos)
                    # for typing_key due to performance reasons and due to their highly
                    # ephemeral nature.
                    #
                    # Instead we simply grab the latest typing updates in _handle_typing
                    # and, if they apply to this application service, send it off.
                    events = await self._handle_typing(service, new_token)
                    if events:
                        self.scheduler.enqueue_for_appservice(service, ephemeral=events)
                    continue

                # Since we read/update the stream position for this AS/stream
                async with self._ephemeral_events_linearizer.queue(
                    (service.id, stream_key)
                ):
                    if stream_key == StreamKeyType.RECEIPT:
                        events = await self._handle_receipts(service, new_token)
                        self.scheduler.enqueue_for_appservice(service, ephemeral=events)

                        # Persist the latest handled stream token for this appservice
                        await self.store.set_appservice_stream_type_pos(
                            service, "read_receipt", new_token
                        )

                    elif stream_key == StreamKeyType.PRESENCE:
                        events = await self._handle_presence(service, users, new_token)
                        self.scheduler.enqueue_for_appservice(service, ephemeral=events)

                        # Persist the latest handled stream token for this appservice
                        await self.store.set_appservice_stream_type_pos(
                            service, "presence", new_token
                        )

                    elif stream_key == StreamKeyType.TO_DEVICE:
                        # Retrieve a list of to-device message events, as well as the
                        # maximum stream token of the messages we were able to retrieve.
                        to_device_messages = await self._get_to_device_messages(
                            service, new_token, users
                        )
                        self.scheduler.enqueue_for_appservice(
                            service, to_device_messages=to_device_messages
                        )

                        # Persist the latest handled stream token for this appservice
                        await self.store.set_appservice_stream_type_pos(
                            service, "to_device", new_token
                        )

                    elif stream_key == StreamKeyType.DEVICE_LIST:
                        device_list_summary = await self._get_device_list_summary(
                            service, new_token
                        )
                        if device_list_summary:
                            self.scheduler.enqueue_for_appservice(
                                service, device_list_summary=device_list_summary
                            )

                        # Persist the latest handled stream token for this appservice
                        await self.store.set_appservice_stream_type_pos(
                            service, "device_list", new_token
                        )

    async def _handle_typing(
        self, service: ApplicationService, new_token: int
    ) -> List[JsonDict]:
        """
        Return the typing events since the given stream token that the given application
        service should receive.

        First fetch all typing events between the given typing stream token (non-inclusive)
        and the latest typing event stream token (inclusive). Then return only those typing
        events that the given application service may be interested in.

        Args:
            service: The application service to check for which events it should receive.
            new_token: A typing event stream token.

        Returns:
            A list of JSON dictionaries containing data derived from the typing events that
            should be sent to the given application service.
        """
        typing_source = self.event_sources.sources.typing
        # Get the typing events from just before current
        typing, _ = await typing_source.get_new_events_as(
            service=service,
            # For performance reasons, we don't persist the previous
            # token in the DB and instead fetch the latest typing event
            # for appservices.
            # TODO: It'd likely be more efficient to simply fetch the
            #  typing event with the given 'new_token' stream token and
            #  check if the given service was interested, rather than
            #  iterating over all typing events and only grabbing the
            #  latest few.
            from_key=new_token - 1,
        )
        return typing

    async def _handle_receipts(
        self, service: ApplicationService, new_token: int
    ) -> List[JsonDict]:
        """
        Return the latest read receipts that the given application service should receive.

        First fetch all read receipts between the last receipt stream token that this
        application service should have previously received (non-inclusive) and the
        latest read receipt stream token (inclusive). Then from that set, return only
        those read receipts that the given application service may be interested in.

        Args:
            service: The application service to check for which events it should receive.
            new_token: A receipts event stream token. Purely used to double-check that the
                from_token we pull from the database isn't greater than or equal to this
                token. Prevents accidentally duplicating work.

        Returns:
            A list of JSON dictionaries containing data derived from the read receipts that
            should be sent to the given application service.
        """
        from_key = await self.store.get_type_stream_id_for_appservice(
            service, "read_receipt"
        )
        if new_token is not None and new_token <= from_key:
            logger.debug(
                "Rejecting token lower than or equal to stored: %s" % (new_token,)
            )
            return []

        receipts_source = self.event_sources.sources.receipt
        receipts, _ = await receipts_source.get_new_events_as(
            service=service, from_key=from_key, to_key=new_token
        )
        return receipts

    async def _handle_presence(
        self,
        service: ApplicationService,
        users: Collection[Union[str, UserID]],
        new_token: Optional[int],
    ) -> List[JsonDict]:
        """
        Return the latest presence updates that the given application service should receive.

        First, filter the given users list to those that the application service is
        interested in. Then retrieve the latest presence updates since the
        the last-known previously received presence stream token for the given
        application service. Return those presence updates.

        Args:
            service: The application service that ephemeral events are being sent to.
            users: The users that should receive the presence update.
            new_token: A presence update stream token. Purely used to double-check that the
                from_token we pull from the database isn't greater than or equal to this
                token. Prevents accidentally duplicating work.

        Returns:
            A list of json dictionaries containing data derived from the presence events
            that should be sent to the given application service.
        """
        events: List[JsonDict] = []
        presence_source = self.event_sources.sources.presence
        from_key = await self.store.get_type_stream_id_for_appservice(
            service, "presence"
        )
        if new_token is not None and new_token <= from_key:
            logger.debug(
                "Rejecting token lower than or equal to stored: %s" % (new_token,)
            )
            return []

        for user in users:
            if isinstance(user, str):
                user = UserID.from_string(user)

            interested = await service.is_interested_in_presence(user, self.store)
            if not interested:
                continue

            presence_events, _ = await presence_source.get_new_events(
                user=user,
                from_key=from_key,
            )
            time_now = self.clock.time_msec()
            events.extend(
                {
                    "type": EduTypes.PRESENCE,
                    "sender": event.user_id,
                    "content": format_user_presence_state(
                        event, time_now, include_user_id=False
                    ),
                }
                for event in presence_events
            )

        return events

    async def _get_to_device_messages(
        self,
        service: ApplicationService,
        new_token: int,
        users: Collection[Union[str, UserID]],
    ) -> List[JsonDict]:
        """
        Given an application service, determine which events it should receive
        from those between the last-recorded to-device message stream token for this
        appservice and the given stream token.

        Args:
            service: The application service to check for which events it should receive.
            new_token: The latest to-device event stream token.
            users: The users to be notified for the new to-device messages
                (ie, the recipients of the messages).

        Returns:
            A list of JSON dictionaries containing data derived from the to-device events
                that should be sent to the given application service.
        """
        # Get the stream token that this application service has processed up until
        from_key = await self.store.get_type_stream_id_for_appservice(
            service, "to_device"
        )

        # Filter out users that this appservice is not interested in
        users_appservice_is_interested_in: List[str] = []
        for user in users:
            # FIXME: We should do this farther up the call stack. We currently repeat
            #  this operation in _handle_presence.
            if isinstance(user, UserID):
                user = user.to_string()

            if service.is_interested_in_user(user):
                users_appservice_is_interested_in.append(user)

        if not users_appservice_is_interested_in:
            # Return early if the AS was not interested in any of these users
            return []

        # Retrieve the to-device messages for each user
        recipient_device_to_messages = await self.store.get_messages_for_user_devices(
            users_appservice_is_interested_in,
            from_key,
            new_token,
        )

        # According to MSC2409, we'll need to add 'to_user_id' and 'to_device_id' fields
        # to the event JSON so that the application service will know which user/device
        # combination this messages was intended for.
        #
        # So we mangle this dict into a flat list of to-device messages with the relevant
        # user ID and device ID embedded inside each message dict.
        message_payload: List[JsonDict] = []
        for (
            user_id,
            device_id,
        ), messages in recipient_device_to_messages.items():
            for message_json in messages:
                # Remove 'message_id' from the to-device message, as it's an internal ID
                message_json.pop("message_id", None)

                message_payload.append(
                    {
                        "to_user_id": user_id,
                        "to_device_id": device_id,
                        **message_json,
                    }
                )

        return message_payload

    async def _get_device_list_summary(
        self,
        appservice: ApplicationService,
        new_key: int,
    ) -> DeviceListUpdates:
        """
        Retrieve a list of users who have changed their device lists.

        Args:
            appservice: The application service to retrieve device list changes for.
            new_key: The stream key of the device list change that triggered this method call.

        Returns:
            A set of device list updates, comprised of users that the appservices needs to:
                * resync the device list of, and
                * stop tracking the device list of.
        """
        # Fetch the last successfully processed device list update stream ID
        # for this appservice.
        from_key = await self.store.get_type_stream_id_for_appservice(
            appservice, "device_list"
        )

        # Fetch the users who have modified their device list since then.
        users_with_changed_device_lists = (
            await self.store.get_users_whose_devices_changed(from_key, to_key=new_key)
        )

        # Filter out any users the application service is not interested in
        #
        # For each user who changed their device list, we want to check whether this
        # appservice would be interested in the change.
        filtered_users_with_changed_device_lists = {
            user_id
            for user_id in users_with_changed_device_lists
            if await self._is_appservice_interested_in_device_lists_of_user(
                appservice, user_id
            )
        }

        # Create a summary of "changed" and "left" users.
        # TODO: Calculate "left" users.
        device_list_summary = DeviceListUpdates(
            changed=filtered_users_with_changed_device_lists
        )

        return device_list_summary

    async def _is_appservice_interested_in_device_lists_of_user(
        self,
        appservice: ApplicationService,
        user_id: str,
    ) -> bool:
        """
        Returns whether a given application service is interested in the device list
        updates of a given user.

        The application service is interested in the user's device list updates if any
        of the following are true:
            * The user is the appservice's sender localpart user.
            * The user is in the appservice's user namespace.
            * At least one member of one room that the user is a part of is in the
              appservice's user namespace.
            * The appservice is explicitly (via room ID or alias) interested in at
              least one room that the user is in.

        Args:
            appservice: The application service to gauge interest of.
            user_id: The ID of the user whose device list interest is in question.

        Returns:
            True if the application service is interested in the user's device lists, False
            otherwise.
        """
        # This method checks against both the sender localpart user as well as if the
        # user is in the appservice's user namespace.
        if appservice.is_interested_in_user(user_id):
            return True

        # Determine whether any of the rooms the user is in justifies sending this
        # device list update to the application service.
        room_ids = await self.store.get_rooms_for_user(user_id)
        for room_id in room_ids:
            # This method covers checking room members for appservice interest as well as
            # room ID and alias checks.
            if await appservice.is_interested_in_room(room_id, self.store):
                return True

        return False

    async def query_user_exists(self, user_id: str) -> bool:
        """Check if any application service knows this user_id exists.

        Args:
            user_id: The user to query if they exist on any AS.
        Returns:
            True if this user exists on at least one application service.
        """
        user_query_services = self._get_services_for_user(user_id=user_id)
        for user_service in user_query_services:
            is_known_user = await self.appservice_api.query_user(user_service, user_id)
            if is_known_user:
                return True
        return False

    async def query_room_alias_exists(
        self, room_alias: RoomAlias
    ) -> Optional[RoomAliasMapping]:
        """Check if an application service knows this room alias exists.

        Args:
            room_alias: The room alias to query.

        Returns:
            RoomAliasMapping or None if no association can be found.
        """
        room_alias_str = room_alias.to_string()
        services = self.store.get_app_services()
        alias_query_services = [
            s for s in services if (s.is_room_alias_in_namespace(room_alias_str))
        ]
        for alias_service in alias_query_services:
            is_known_alias = await self.appservice_api.query_alias(
                alias_service, room_alias_str
            )
            if is_known_alias:
                # the alias exists now so don't query more ASes.
                return await self.store.get_association_from_room_alias(room_alias)

        return None

    async def query_3pe(
        self, kind: str, protocol: str, fields: Dict[bytes, List[bytes]]
    ) -> List[JsonDict]:
        services = self._get_services_for_3pn(protocol)

        results = await make_deferred_yieldable(
            defer.DeferredList(
                [
                    run_in_background(
                        self.appservice_api.query_3pe, service, kind, protocol, fields
                    )
                    for service in services
                ],
                consumeErrors=True,
            )
        )

        ret = []
        for (success, result) in results:
            if success:
                ret.extend(result)

        return ret

    async def get_3pe_protocols(
        self, only_protocol: Optional[str] = None
    ) -> Dict[str, JsonDict]:
        services = self.store.get_app_services()
        protocols: Dict[str, List[JsonDict]] = {}

        # Collect up all the individual protocol responses out of the ASes
        for s in services:
            for p in s.protocols:
                if only_protocol is not None and p != only_protocol:
                    continue

                if p not in protocols:
                    protocols[p] = []

                info = await self.appservice_api.get_3pe_protocol(s, p)

                if info is not None:
                    protocols[p].append(info)

        def _merge_instances(infos: List[JsonDict]) -> JsonDict:
            # Merge the 'instances' lists of multiple results, but just take
            # the other fields from the first as they ought to be identical
            # copy the result so as not to corrupt the cached one
            combined = dict(infos[0])
            combined["instances"] = list(combined["instances"])

            for info in infos[1:]:
                combined["instances"].extend(info["instances"])

            return combined

        return {
            p: _merge_instances(protocols[p]) for p in protocols.keys() if protocols[p]
        }

    async def _get_services_for_event(
        self, event: EventBase
    ) -> List[ApplicationService]:
        """Retrieve a list of application services interested in this event.

        Args:
            event: The event to check.
        Returns:
            A list of services interested in this event based on the service regex.
        """
        services = self.store.get_app_services()

        # we can't use a list comprehension here. Since python 3, list
        # comprehensions use a generator internally. This means you can't yield
        # inside of a list comprehension anymore.
        interested_list = []
        for s in services:
            if await s.is_interested_in_event(event.event_id, event, self.store):
                interested_list.append(s)

        return interested_list

    def _get_services_for_user(self, user_id: str) -> List[ApplicationService]:
        services = self.store.get_app_services()
        return [s for s in services if (s.is_interested_in_user(user_id))]

    def _get_services_for_3pn(self, protocol: str) -> List[ApplicationService]:
        services = self.store.get_app_services()
        return [s for s in services if s.is_interested_in_protocol(protocol)]

    async def _is_unknown_user(self, user_id: str) -> bool:
        if not self.is_mine_id(user_id):
            # we don't know if they are unknown or not since it isn't one of our
            # users. We can't poke ASes.
            return False

        user_info = await self.store.get_user_by_id(user_id)
        if user_info:
            return False

        # user not found; could be the AS though, so check.
        services = self.store.get_app_services()
        service_list = [s for s in services if s.sender == user_id]
        return len(service_list) == 0

    async def _check_user_exists(self, user_id: str) -> bool:
        unknown_user = await self._is_unknown_user(user_id)
        if unknown_user:
            return await self.query_user_exists(user_id)
        return True
