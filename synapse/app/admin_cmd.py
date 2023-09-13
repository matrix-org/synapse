# Copyright 2019 Matrix.org Foundation C.I.C.
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
import argparse
import json
import logging
import os
import sys
import tempfile
from typing import List, Mapping, Optional, Sequence

from twisted.internet import defer, task

import synapse
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.events import EventBase
from synapse.handlers.admin import ExfiltrationWriter
from synapse.server import HomeServer
from synapse.storage.database import DatabasePool, LoggingDatabaseConnection
from synapse.storage.databases.main.account_data import AccountDataWorkerStore
from synapse.storage.databases.main.appservice import (
    ApplicationServiceTransactionWorkerStore,
    ApplicationServiceWorkerStore,
)
from synapse.storage.databases.main.client_ips import ClientIpWorkerStore
from synapse.storage.databases.main.deviceinbox import DeviceInboxWorkerStore
from synapse.storage.databases.main.devices import DeviceWorkerStore
from synapse.storage.databases.main.event_federation import EventFederationWorkerStore
from synapse.storage.databases.main.event_push_actions import (
    EventPushActionsWorkerStore,
)
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.databases.main.filtering import FilteringWorkerStore
from synapse.storage.databases.main.media_repository import MediaRepositoryStore
from synapse.storage.databases.main.profile import ProfileWorkerStore
from synapse.storage.databases.main.push_rule import PushRulesWorkerStore
from synapse.storage.databases.main.receipts import ReceiptsWorkerStore
from synapse.storage.databases.main.registration import RegistrationWorkerStore
from synapse.storage.databases.main.relations import RelationsWorkerStore
from synapse.storage.databases.main.room import RoomWorkerStore
from synapse.storage.databases.main.roommember import RoomMemberWorkerStore
from synapse.storage.databases.main.signatures import SignatureWorkerStore
from synapse.storage.databases.main.state import StateGroupWorkerStore
from synapse.storage.databases.main.stream import StreamWorkerStore
from synapse.storage.databases.main.tags import TagsWorkerStore
from synapse.storage.databases.main.user_erasure_store import UserErasureWorkerStore
from synapse.types import JsonMapping, StateMap
from synapse.util import SYNAPSE_VERSION
from synapse.util.logcontext import LoggingContext

logger = logging.getLogger("synapse.app.admin_cmd")


class AdminCmdStore(
    FilteringWorkerStore,
    ClientIpWorkerStore,
    DeviceWorkerStore,
    TagsWorkerStore,
    DeviceInboxWorkerStore,
    AccountDataWorkerStore,
    PushRulesWorkerStore,
    ApplicationServiceTransactionWorkerStore,
    ApplicationServiceWorkerStore,
    RoomMemberWorkerStore,
    RelationsWorkerStore,
    EventFederationWorkerStore,
    EventPushActionsWorkerStore,
    StateGroupWorkerStore,
    SignatureWorkerStore,
    UserErasureWorkerStore,
    ReceiptsWorkerStore,
    StreamWorkerStore,
    EventsWorkerStore,
    RegistrationWorkerStore,
    RoomWorkerStore,
    ProfileWorkerStore,
    MediaRepositoryStore,
):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # Annoyingly `filter_events_for_client` assumes that this exists. We
        # should refactor it to take a `Clock` directly.
        self.clock = hs.get_clock()


class AdminCmdServer(HomeServer):
    DATASTORE_CLASS = AdminCmdStore  # type: ignore


async def export_data_command(hs: HomeServer, args: argparse.Namespace) -> None:
    """Export data for a user."""

    user_id = args.user_id
    directory = args.output_directory

    res = await hs.get_admin_handler().export_user_data(
        user_id, FileExfiltrationWriter(user_id, directory=directory)
    )
    print(res)


class FileExfiltrationWriter(ExfiltrationWriter):
    """An ExfiltrationWriter that writes the users data to a directory.
    Returns the directory location on completion.

    Note: This writes to disk on the main reactor thread.

    Args:
        user_id: The user whose data is being exfiltrated.
        directory: The directory to write the data to, if None then will write
            to a temporary directory.
    """

    def __init__(self, user_id: str, directory: Optional[str] = None):
        self.user_id = user_id

        if directory:
            self.base_directory = directory
        else:
            self.base_directory = tempfile.mkdtemp(
                prefix="synapse-exfiltrate__%s__" % (user_id,)
            )

        os.makedirs(self.base_directory, exist_ok=True)
        if list(os.listdir(self.base_directory)):
            raise Exception("Directory must be empty")

    def write_events(self, room_id: str, events: List[EventBase]) -> None:
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        os.makedirs(room_directory, exist_ok=True)
        events_file = os.path.join(room_directory, "events")

        with open(events_file, "a") as f:
            for event in events:
                json.dump(event.get_pdu_json(), fp=f)

    def write_state(
        self, room_id: str, event_id: str, state: StateMap[EventBase]
    ) -> None:
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        state_directory = os.path.join(room_directory, "state")
        os.makedirs(state_directory, exist_ok=True)

        event_file = os.path.join(state_directory, event_id)

        with open(event_file, "a") as f:
            for event in state.values():
                json.dump(event.get_pdu_json(), fp=f)

    def write_invite(
        self, room_id: str, event: EventBase, state: StateMap[EventBase]
    ) -> None:
        self.write_events(room_id, [event])

        # We write the invite state somewhere else as they aren't full events
        # and are only a subset of the state at the event.
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        os.makedirs(room_directory, exist_ok=True)

        invite_state = os.path.join(room_directory, "invite_state")

        with open(invite_state, "a") as f:
            for event in state.values():
                json.dump(event, fp=f)

    def write_knock(
        self, room_id: str, event: EventBase, state: StateMap[EventBase]
    ) -> None:
        self.write_events(room_id, [event])

        # We write the knock state somewhere else as they aren't full events
        # and are only a subset of the state at the event.
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        os.makedirs(room_directory, exist_ok=True)

        knock_state = os.path.join(room_directory, "knock_state")

        with open(knock_state, "a") as f:
            for event in state.values():
                json.dump(event, fp=f)

    def write_profile(self, profile: JsonMapping) -> None:
        user_directory = os.path.join(self.base_directory, "user_data")
        os.makedirs(user_directory, exist_ok=True)
        profile_file = os.path.join(user_directory, "profile")

        with open(profile_file, "a") as f:
            json.dump(profile, fp=f)

    def write_devices(self, devices: Sequence[JsonMapping]) -> None:
        user_directory = os.path.join(self.base_directory, "user_data")
        os.makedirs(user_directory, exist_ok=True)
        device_file = os.path.join(user_directory, "devices")

        for device in devices:
            with open(device_file, "a") as f:
                json.dump(device, fp=f)

    def write_connections(self, connections: Sequence[JsonMapping]) -> None:
        user_directory = os.path.join(self.base_directory, "user_data")
        os.makedirs(user_directory, exist_ok=True)
        connection_file = os.path.join(user_directory, "connections")

        for connection in connections:
            with open(connection_file, "a") as f:
                json.dump(connection, fp=f)

    def write_account_data(
        self, file_name: str, account_data: Mapping[str, JsonMapping]
    ) -> None:
        account_data_directory = os.path.join(
            self.base_directory, "user_data", "account_data"
        )
        os.makedirs(account_data_directory, exist_ok=True)

        account_data_file = os.path.join(account_data_directory, file_name)

        with open(account_data_file, "a") as f:
            json.dump(account_data, fp=f)

    def write_media_id(self, media_id: str, media_metadata: JsonMapping) -> None:
        file_directory = os.path.join(self.base_directory, "media_ids")
        os.makedirs(file_directory, exist_ok=True)
        media_id_file = os.path.join(file_directory, media_id)

        with open(media_id_file, "w") as f:
            json.dump(media_metadata, fp=f)

    def finished(self) -> str:
        return self.base_directory


def start(config_options: List[str]) -> None:
    parser = argparse.ArgumentParser(description="Synapse Admin Command")
    HomeServerConfig.add_arguments_to_parser(parser)

    subparser = parser.add_subparsers(
        title="Admin Commands",
        required=True,
        dest="command",
        metavar="<admin_command>",
        help="The admin command to perform.",
    )
    export_data_parser = subparser.add_parser(
        "export-data", help="Export all data for a user"
    )
    export_data_parser.add_argument("user_id", help="User to extra data from")
    export_data_parser.add_argument(
        "--output-directory",
        action="store",
        metavar="DIRECTORY",
        required=False,
        help="The directory to store the exported data in. Must be empty. Defaults"
        " to creating a temp directory.",
    )
    export_data_parser.set_defaults(func=export_data_command)

    try:
        config, args = HomeServerConfig.load_config_with_parser(parser, config_options)
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    if config.worker.worker_app is not None:
        assert config.worker.worker_app == "synapse.app.admin_cmd"

    # Update the config with some basic overrides so that don't have to specify
    # a full worker config.
    config.worker.worker_app = "synapse.app.admin_cmd"

    if not config.worker.worker_daemonize and not config.worker.worker_log_config:
        # Since we're meant to be run as a "command" let's not redirect stdio
        # unless we've actually set log config.
        config.logging.no_redirect_stdio = True

    # Explicitly disable background processes
    config.worker.should_update_user_directory = False
    config.worker.run_background_tasks = False
    config.worker.start_pushers = False
    config.worker.pusher_shard_config.instances = []
    config.worker.send_federation = False
    config.worker.federation_shard_config.instances = []

    synapse.events.USE_FROZEN_DICTS = config.server.use_frozen_dicts

    ss = AdminCmdServer(
        config.server.server_name,
        config=config,
        version_string=f"Synapse/{SYNAPSE_VERSION}",
    )

    setup_logging(ss, config, use_worker_options=True)

    ss.setup()

    # We use task.react as the basic run command as it correctly handles tearing
    # down the reactor when the deferreds resolve and setting the return value.
    # We also make sure that `_base.start` gets run before we actually run the
    # command.

    async def run() -> None:
        with LoggingContext("command"):
            await _base.start(ss)
            await args.func(ss, args)

    _base.start_worker_reactor(
        "synapse-admin-cmd",
        config,
        run_command=lambda: task.react(lambda _reactor: defer.ensureDeferred(run())),
    )


if __name__ == "__main__":
    with LoggingContext("main"):
        start(sys.argv[1:])
