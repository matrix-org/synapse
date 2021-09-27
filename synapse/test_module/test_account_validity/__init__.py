from typing import Optional

from synapse.module_api import ModuleApi


class DummyAccountValidity:
    def __init__(self, config: dict, api: ModuleApi):
        api.register_account_validity_callbacks(is_user_expired=self.is_user_expired)

    async def is_user_expired(self, user_id: str) -> Optional[bool]:
        return False
