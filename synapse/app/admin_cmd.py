#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
import logging
import os
import sys
import tempfile

from canonicaljson import json

from twisted.internet import defer, task

import synapse
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.handlers.admin import ExfiltrationWriter
from synapse.replication.slave.storage._base import BaseSlavedStore
from synapse.replication.slave.storage.account_data import SlavedAccountDataStore
from synapse.replication.slave.storage.appservice import SlavedApplicationServiceStore
from synapse.replication.slave.storage.client_ips import SlavedClientIpStore
from synapse.replication.slave.storage.deviceinbox import SlavedDeviceInboxStore
from synapse.replication.slave.storage.devices import SlavedDeviceStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.filtering import SlavedFilteringStore
from synapse.replication.slave.storage.groups import SlavedGroupServerStore
from synapse.replication.slave.storage.presence import SlavedPresenceStore
from synapse.replication.slave.storage.push_rule import SlavedPushRuleStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.slave.storage.room import RoomStore
from synapse.server import HomeServer
from synapse.util.logcontext import LoggingContext
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.admin_cmd")


class AdminCmdSlavedStore(
    SlavedReceiptsStore,
    SlavedAccountDataStore,
    SlavedApplicationServiceStore,
    SlavedRegistrationStore,
    SlavedFilteringStore,
    SlavedPresenceStore,
    SlavedGroupServerStore,
    SlavedDeviceInboxStore,
    SlavedDeviceStore,
    SlavedPushRuleStore,
    SlavedEventStore,
    SlavedClientIpStore,
    RoomStore,
    BaseSlavedStore,
):
    pass


class AdminCmdServer(HomeServer):
    DATASTORE_CLASS = AdminCmdSlavedStore

    def _listen_http(self, listener_config):
        pass

    def start_listening(self, listeners):
        pass


@defer.inlineCallbacks
def export_data_command(hs, args):
    """Export data for a user.

    Args:
        hs (HomeServer)
        args (argparse.Namespace)
    """

    user_id = args.user_id
    directory = args.output_directory

    res = yield defer.ensureDeferred(
        hs.get_handlers().admin_handler.export_user_data(
            user_id, FileExfiltrationWriter(user_id, directory=directory)
        )
    )
    print(res)


class FileExfiltrationWriter(ExfiltrationWriter):
    """An ExfiltrationWriter that writes the users data to a directory.
    Returns the directory location on completion.

    Note: This writes to disk on the main reactor thread.

    Args:
        user_id (str): The user whose data is being exfiltrated.
        directory (str|None): The directory to write the data to, if None then
            will write to a temporary directory.
    """

    def __init__(self, user_id, directory=None):
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

    def write_events(self, room_id, events):
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        os.makedirs(room_directory, exist_ok=True)
        events_file = os.path.join(room_directory, "events")

        with open(events_file, "a") as f:
            for event in events:
                print(json.dumps(event.get_pdu_json()), file=f)

    def write_state(self, room_id, event_id, state):
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        state_directory = os.path.join(room_directory, "state")
        os.makedirs(state_directory, exist_ok=True)

        event_file = os.path.join(state_directory, event_id)

        with open(event_file, "a") as f:
            for event in state.values():
                print(json.dumps(event.get_pdu_json()), file=f)

    def write_invite(self, room_id, event, state):
        self.write_events(room_id, [event])

        # We write the invite state somewhere else as they aren't full events
        # and are only a subset of the state at the event.
        room_directory = os.path.join(self.base_directory, "rooms", room_id)
        os.makedirs(room_directory, exist_ok=True)

        invite_state = os.path.join(room_directory, "invite_state")

        with open(invite_state, "a") as f:
            for event in state.values():
                print(json.dumps(event), file=f)

    def finished(self):
        return self.base_directory


def start(config_options):
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

    if config.worker_app is not None:
        assert config.worker_app == "synapse.app.admin_cmd"

    # Update the config with some basic overrides so that don't have to specify
    # a full worker config.
    config.worker_app = "synapse.app.admin_cmd"

    if (
        not config.worker_daemonize
        and not config.worker_log_file
        and not config.worker_log_config
    ):
        # Since we're meant to be run as a "command" let's not redirect stdio
        # unless we've actually set log config.
        config.no_redirect_stdio = True

    # Explicitly disable background processes
    config.update_user_directory = False
    config.start_pushers = False
    config.send_federation = False

    synapse.events.USE_FROZEN_DICTS = config.use_frozen_dicts

    ss = AdminCmdServer(
        config.server_name,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
    )

    setup_logging(ss, config, use_worker_options=True)

    ss.setup()

    # We use task.react as the basic run command as it correctly handles tearing
    # down the reactor when the deferreds resolve and setting the return value.
    # We also make sure that `_base.start` gets run before we actually run the
    # command.

    @defer.inlineCallbacks
    def run(_reactor):
        with LoggingContext("command"):
            yield _base.start(ss, [])
            yield args.func(ss, args)

    _base.start_worker_reactor(
        "synapse-admin-cmd", config, run_command=lambda: task.react(run)
    )


if __name__ == "__main__":
    with LoggingContext("main"):
        start(sys.argv[1:])
