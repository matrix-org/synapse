# Account data callbacks

Account data callbacks allow module developers to react to changes of the account data
of local users. Account data callbacks can be registered using the module API's
`register_account_data_callbacks` method.

## Callbacks

The available account data callbacks are:

### `on_account_data_updated`

_First introduced in Synapse v1.57.0_

```python
async def on_account_data_updated(
    user_id: str,
    room_id: Optional[str],
    account_data_type: str,
    content: "synapse.module_api.JsonDict",
) -> None:
```

Called after user's account data has been updated. The module is given the
Matrix ID of the user whose account data is changing, the room ID the data is associated
with, the type associated with the change, as well as the new content. If the account
data is not associated with a specific room, then the room ID is `None`.

This callback is triggered when new account data is added or when the data associated with
a given type (and optionally room) changes. This includes deletion, since in Matrix,
deleting account data consists of replacing the data associated with a given type
(and optionally room) with an empty dictionary (`{}`).

Note that this doesn't trigger when changing the tags associated with a room, as these are
processed separately by Synapse.

If multiple modules implement this callback, Synapse runs them all in order.

## Example

The example below is a module that implements the `on_account_data_updated` callback, and
sends an event to an audit room when a user changes their account data.

```python
import json
import attr
from typing import Any, Dict, Optional

from synapse.module_api import JsonDict, ModuleApi
from synapse.module_api.errors import ConfigError


@attr.s(auto_attribs=True)
class CustomAccountDataConfig:
    audit_room: str
    sender: str


class CustomAccountDataModule:
    def __init__(self, config: CustomAccountDataConfig, api: ModuleApi):
        self.api = api
        self.config = config

        self.api.register_account_data_callbacks(
            on_account_data_updated=self.log_new_account_data,
        )

    @staticmethod
    def parse_config(config: Dict[str, Any]) -> CustomAccountDataConfig:
        def check_in_config(param: str):
            if param not in config:
                raise ConfigError(f"'{param}' is required")

        check_in_config("audit_room")
        check_in_config("sender")

        return CustomAccountDataConfig(
            audit_room=config["audit_room"],
            sender=config["sender"],
        )

    async def log_new_account_data(
        self,
        user_id: str,
        room_id: Optional[str],
        account_data_type: str,
        content: JsonDict,
    ) -> None:
        content_raw = json.dumps(content)
        msg_content = f"{user_id} has changed their account data for type {account_data_type} to: {content_raw}"

        if room_id is not None:
            msg_content += f" (in room {room_id})"

        await self.api.create_and_send_event_into_room(
            {
                "room_id": self.config.audit_room,
                "sender": self.config.sender,
                "type": "m.room.message",
                "content": {
                    "msgtype": "m.text",
                    "body": msg_content
                }
            }
        )
```
