# Account validity

Synapse supports checking the validity of an account against one or more plugin module(s).

An account validity plugin module is a Python class that exposes two functions:

* `is_user_expired`, which checks if the account for the provided Matrix user ID has
  expired. It returns a boolean to indicate whether the account has expired, or None if
  it failed to figure it out. If this function returns `True`, Synapse will block any
  request (apart from logout ones). If it returns `None`, Synapse will ask the next
  module (in the order they appear in Synapse's configuration file), or consider the user
  as not expired if it's reached the end of the list.
* `on_user_registration`, which is called after any successful registration
  with the Matrix ID of the newly registered user.


## Example

```python
import time
from typing import Optional

from synapse.module_api import ModuleApi

from my_module.store import Store, StoreException

class ExampleAccountValidity:
    def __init__(self, config: dict, api: ModuleApi):
        self.config = config
        self.api = api
        self.store = Store(config, api)

    @staticmethod
    def parse_config(config):
        return config

    async def is_user_expired(self, user_id: str) -> Optional[bool]:
        now_ms = time.time() * 1000
        
        # Try to figure out what the expiration date for this account is and whether the
        # account has expired, return None if that failed.
        try:
            expiration_ts = await self.store.get_expiration_ts(user_id)
            return expiration_ts <= now_ms
        except StoreException:
            return None

    async def on_user_registration(self, user_id: str) -> None:
        await self.store.insert_user(user_id)
```