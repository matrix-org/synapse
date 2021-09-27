import time

from synapse.api.constants import EventTypes
from synapse.events import EventBase
from synapse.module_api import ModuleApi
from synapse.types import StateMap


class MySuperModule:
    def __init__(self, config: dict, api: ModuleApi):
        self.api = api

        self.api.register_third_party_rules_callbacks(
            check_event_allowed=self.check_event_allowed,
        )

    async def check_event_allowed(self, event: EventBase, state: StateMap[EventBase]):
        if event.is_state() and event.type == EventTypes.Member:
            await self.api.create_and_send_event_into_room(
                {
                    "room_id": event.room_id,
                    "sender": event.sender,
                    "type": "bzh.abolivier.test3",
                    "content": {"now": int(time.time())},
                    "state_key": "",
                }
            )

        return True, None
