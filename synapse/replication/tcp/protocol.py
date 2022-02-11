# Copyright 2017 Vector Creations Ltd
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
from prometheus_client import Counter
from zope.interface import Interface

from synapse.replication.tcp.commands import Command

tcp_inbound_commands_counter = Counter(
    "synapse_replication_tcp_protocol_inbound_commands",
    "Number of commands received from replication, by command and name of process connected to",
    ["command", "name"],
)

tcp_outbound_commands_counter = Counter(
    "synapse_replication_tcp_protocol_outbound_commands",
    "Number of commands sent to replication, by command and name of process connected to",
    ["command", "name"],
)


class IReplicationConnection(Interface):
    """An interface for replication connections."""

    def send_command(cmd: Command) -> None:
        """Send the command down the connection"""
