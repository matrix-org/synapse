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
from synapse.logging.context import defer_to_thread
from synapse.metrics.background_process_metrics import run_as_background_process

try:
    import auto_compressor as state_compressor
except ImportError:
    state_compressor = None


def setup_state_compressor(hs):
    """Schedules the state compressor to run regularly"""

    # Return if cannot import auto_compressor
    if not state_compressor:
        return

    # Return if compressor isn't enabled
    compressor_config = hs.config.statecompressor
    if not compressor_config.compressor_enabled:
        return

    # Check that the database being used is postgres
    db_config = hs.config.database.get_single_database().config
    if db_config["name"] != "psycopg2":
        return

    # construct the database URL from the database config
    db_args = db_config["args"]
    db_url = "postgresql://{username}:{password}@{host}:{port}/{database}".format(
        username=db_args["user"],
        password=db_args["password"],
        host=db_args["host"],
        port=db_args["port"],
        database=db_args["database"],
    )

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
