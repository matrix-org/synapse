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
import logging
import sys

from twisted.internet import defer, task

import synapse
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.handlers.admin import FileExfiltrationWriter
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
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.server import HomeServer
from synapse.storage.engines import create_engine
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

    def build_tcp_replication(self):
        return AdminCmdReplicationHandler(self)


class AdminCmdReplicationHandler(ReplicationClientHandler):
    @defer.inlineCallbacks
    def on_rdata(self, stream_name, token, rows):
        pass

    def get_streams_to_replicate(self):
        return {}


@defer.inlineCallbacks
def export_data_command(hs, user_id, directory):
    """Export data for a user.

    Args:
        user_id (str)
        directory (str|None): Directory to write output to. Will create a temp
            directory if not specified.
    """

    res = yield hs.get_handlers().admin_handler.exfiltrate_user_data(
        user_id, FileExfiltrationWriter(user_id, directory=directory)
    )
    print(res)


def start(config_options):
    parser = HomeServerConfig.create_argument_parser("Synapse Admin Command")

    subparser = parser.add_subparsers(
        title="Admin Commands",
        description="Choose an admin command to perform.",
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
        help="The directory to store the exported data in. Must be emtpy. Defaults"
        " to creating a temp directory.",
    )

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

    setup_logging(config, use_worker_options=True)

    synapse.events.USE_FROZEN_DICTS = config.use_frozen_dicts

    database_engine = create_engine(config.database_config)

    ss = AdminCmdServer(
        config.server_name,
        db_config=config.database_config,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
        database_engine=database_engine,
    )

    ss.setup()

    if args.command == "export-data":
        command = lambda: export_data_command(ss, args.user_id, args.output_directory)
    else:
        # This shouldn't happen.
        raise ConfigError("Unknown admin command %s" % (args.command,))

    # We use task.react as the basic run command as it correctly handles tearing
    # down the reactor when the deferreds resolve and setting the return value.
    # We also make sure that `_base.start` gets run before we actually run the
    # command.

    @defer.inlineCallbacks
    def run(_reactor):
        with LoggingContext("command"):
            yield _base.start(ss, [])
            yield command()

    _base.start_worker_reactor(
        "synapse-admin-cmd", config, run_command=lambda: task.react(run)
    )


if __name__ == "__main__":
    with LoggingContext("main"):
        start(sys.argv[1:])
