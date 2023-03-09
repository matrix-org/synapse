# Copyright 2023 The Matrix.org Foundation C.I.C.
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

from .account_validity_callbacks import AccountValidityModuleApiCallbacks
from .background_updater_callbacks import BackgroundUpdaterModuleApiCallbacks
from .presence_router_callbacks import PresenceRouterModuleApiCallbacks
from .spam_checker_callbacks import SpamCheckerModuleApiCallbacks
from .third_party_event_rules_callbacks import ThirdPartyEventRulesModuleApiCallbacks

__all__ = [
    "ModuleApiCallbacks",
]


class ModuleApiCallbacks:
    def __init__(self) -> None:
        self.account_validity = AccountValidityModuleApiCallbacks()
        self.background_updater = BackgroundUpdaterModuleApiCallbacks()
        self.presence_router = PresenceRouterModuleApiCallbacks()
        self.spam_checker = SpamCheckerModuleApiCallbacks()
        self.third_party_event_rules = ThirdPartyEventRulesModuleApiCallbacks()
