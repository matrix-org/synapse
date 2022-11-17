# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from typing import TYPE_CHECKING

from synapse.storage.controllers.persist_events import (
    EventsPersistenceStorageController,
)
from synapse.storage.controllers.purge_events import PurgeEventsStorageController
from synapse.storage.controllers.state import StateStorageController
from synapse.storage.databases import Databases
from synapse.storage.databases.main import DataStore

if TYPE_CHECKING:
    from synapse.server import HomeServer


__all__ = ["Databases", "DataStore"]


class StorageControllers:
    """The high level interfaces for talking to various storage controller layers."""

    def __init__(self, hs: "HomeServer", stores: Databases):
        # We include the main data store here mainly so that we don't have to
        # rewrite all the existing code to split it into high vs low level
        # interfaces.
        self.main = stores.main

        self.purge_events = PurgeEventsStorageController(hs, stores)
        self.state = StateStorageController(hs, stores)

        self.persistence = None
        if stores.persist_events:
            self.persistence = EventsPersistenceStorageController(hs, stores)
