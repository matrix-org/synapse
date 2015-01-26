import collections


SyncConfig = collections.namedtuple("SyncConfig", [
    "user",
    "device",
    "since",
    "limit",
    "gap",
    "sort"
    "backfill"
    "filter",
)


RoomSyncResult = collections.namedtuple("RoomSyncResult", [
    "room_id",
    "limited",
    "published",
    "prev_batch",
    "events",
    "state",
    "event_map",
])


class SyncResult(collections.namedtuple("SyncResult", [
    "next_batch", # Token for the next sync
    "private_user_data", # List of private events for the user.
    "public_user_data", # List of public events for all users.
    "rooms", # RoomSyncResult for each room.
])):
    __slots__ = []

    def __nonzero__(self):
        return self.private_user_data or self.public_user_data or self.rooms


class SyncHandler(BaseHandler):

    def __init__(self, hs):
        super(SyncHandler, self).__init__(hs)
        self.event_sources = hs.get_event_sources()

    def wait_for_sync_for_user(self, sync_config, since_token=None, timeout=0):
        if timeout == 0:
            return self.current_sync_for_user(sync_config, since)
        else:
            def current_sync_callback(since_token):
                return self.current_sync_for_user(
                    self, since_token, sync_config
                )
            return self.notifier.wait_for_events(
                sync_config.filter, since_token, current_sync_callback
            )
        defer.returnValue(result)

    def current_sync_for_user(self, sync_config, since_token=None):
        if since_token is None:
            return self.inital_sync(sync_config)
        else:
            return self.incremental_sync(sync_config)

    @defer.inlineCallbacks
    def initial_sync(self, sync_config):
        now_token = yield self.event_sources.get_current_token()

        presence_stream = self.event_sources.sources["presence"]
        # TODO (markjh): This looks wrong, shouldn't we be getting the presence
        # UP to the present rather than after the present?
        pagination_config = PaginationConfig(from_token=now_token)
        presence, _ = yield presence_stream.get_pagination_rows(
            user, pagination_config.get_source_config("presence"), None
        )
        room_list = yield self.store.get_rooms_for_user_where_membership_is(
            user_id=user_id,
            membership_list=[Membership.INVITE, Membership.JOIN]
        )

        # TODO (markjh): Does public mean "published"?
        published_rooms = yield self.store.get_rooms(is_public=True)
        published_room_ids = set(r["room_id"] for r in public_rooms)

        for event in room_list:

            messages, token = yield self.store.get_recent_events_for_room(
                event.room_id,
                limit=sync_config.limit,
                end_token=now_token.room_key,
            )
            prev_batch_token = now_token.copy_and_replace("room_key", token[0])
            current_state = yield self.state_handler.get_current_state(
                event.room_id
            )

            rooms.append(RoomSyncResult(
                room_id=event.room_id,
                published=event.room_id in published_room_ids,





    @defer.inlineCallbacks
    def incremental_sync(self, sync_config):
        




