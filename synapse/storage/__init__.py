# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018,2019 New Vector Ltd
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

"""
The storage layer is split up into multiple parts to allow Synapse to run
against different configurations of databases (e.g. single or multiple
databases). The `DatabasePool` class represents connections to a single physical
database. The `databases` are classes that talk directly to a `DatabasePool`
instance and have associated schemas, background updates, etc.

On top of the databases are the StorageControllers, located in the
`synapse.storage.controllers` module. These classes provide high level
interfaces that combine calls to multiple `databases`. They are bundled into the
`StorageControllers` singleton for ease of use, and exposed via
`HomeServer.get_storage_controllers()`.

There are also schemas that get applied to every database, regardless of the
data stores associated with them (e.g. the schema version tables), which are
stored in `synapse.storage.schema`.
"""

from synapse.storage.databases import Databases
from synapse.storage.databases.main import DataStore

__all__ = ["Databases", "DataStore"]
