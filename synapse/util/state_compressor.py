# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from synapse.logging.context import defer_to_thread
from synapse.metrics.background_process_metrics import run_as_background_process

try:
    import auto_compressor as state_compressor
except ImportError:
    state_compressor = None

if TYPE_CHECKING:
    from synapse.server import HomeServer


# The postgres connection options that the rust library understands. See
# https://docs.rs/tokio-postgres/0.7.2/tokio_postgres/config/struct.Config.html#keys
_VALID_POSTGRES_CONN_ARGS = {
    "user",
    "password",
    "dbname",
    "options",
    "application_name",
    "sslmode",
    "host",
    "port",
    "connect_timeout",
    "keepalives",
    "keepalives_idle",
    "target_session_attrs",
    "channel_binding",
}


def setup_state_compressor(hs: "HomeServer"):
    """Schedules the state compressor to run regularly"""

    # Return if cannot import auto_compressor
    if not state_compressor or not hs.config.workers.run_background_tasks:
        return

    # Return if compressor isn't enabled
    compressor_config = hs.config.statecompressor
    if not compressor_config.compressor_enabled:
        return

    # Check that the database being used is postgres
    db_config = hs.config.database.get_single_database().config
    if db_config["name"] != "psycopg2":
        return

    # Construct the database URL from the database config.
    #
    # This is a bit convoluted as the rust postgres library doesn't have a
    # default host/user, so we use the existing Synapse connections to look up
    # what parameters were used there. On the flip side, psycopg2 has some
    # parameters that rust doesn't understand, so we need to filter them out.
    #
    # Note: we need to connect to the *state* database.
    conn_info = hs.get_datastores().state.db_pool.postgres_connection_info
    assert conn_info is not None

    effective_db_args = {}
    for key, value in conn_info.dsn_parameters.items():
        if key in _VALID_POSTGRES_CONN_ARGS:
            effective_db_args[key] = value

    # psycopg2 has a handy util function from going from dictionary to a DSN
    # (postgres connection string.)
    from psycopg2.extensions import make_dsn

    db_url = make_dsn("", **effective_db_args)

    # The method to be called periodically
    def run_state_compressor():
        run_as_background_process(
            desc="State Compressor",
            func=defer_to_thread,
            reactor=hs.get_reactor(),
            f=state_compressor.compress_largest_rooms,
            db_url=db_url,
            chunk_size=compressor_config.compressor_chunk_size,
            default_levels=compressor_config.compressor_default_levels,
            number_of_rooms=compressor_config.compressor_number_of_rooms,
        )

    # Call the compressor every `time_between_runs` milliseconds
    clock = hs.get_clock()
    clock.looping_call(
        run_state_compressor,
        compressor_config.time_between_compressor_runs,
    )
