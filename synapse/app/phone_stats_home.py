#  Copyright 2020 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import logging
import math
import resource
import sys
from typing import TYPE_CHECKING, List, Sized, Tuple

from prometheus_client import Gauge

from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger("synapse.app.homeserver")

# Contains the list of processes we will be monitoring
# currently either 0 or 1
_stats_process: List[Tuple[int, "resource.struct_rusage"]] = []

# Gauges to expose monthly active user control metrics
current_mau_gauge = Gauge("synapse_admin_mau_current", "Current MAU")
current_mau_by_service_gauge = Gauge(
    "synapse_admin_mau_current_mau_by_service",
    "Current MAU by service",
    ["app_service"],
)
max_mau_gauge = Gauge("synapse_admin_mau_max", "MAU Limit")
registered_reserved_users_mau_gauge = Gauge(
    "synapse_admin_mau_registered_reserved_users",
    "Registered users with reserved threepids",
)


@wrap_as_background_process("phone_stats_home")
async def phone_stats_home(
    hs: "HomeServer",
    stats: JsonDict,
    stats_process: List[Tuple[int, "resource.struct_rusage"]] = _stats_process,
) -> None:
    """Collect usage statistics and send them to the configured endpoint.

    Args:
        hs: the HomeServer object to use for gathering usage data.
        stats: the dict in which to store the statistics sent to the configured
            endpoint. Mostly used in tests to figure out the data that is supposed to
            be sent.
        stats_process: statistics about resource usage of the process.
    """

    logger.info("Gathering stats for reporting")
    now = int(hs.get_clock().time())
    # Ensure the homeserver has started.
    assert hs.start_time is not None
    uptime = int(now - hs.start_time)
    if uptime < 0:
        uptime = 0

    #
    # Performance statistics. Keep this early in the function to maintain reliability of `test_performance_100` test.
    #
    old = stats_process[0]
    new = (now, resource.getrusage(resource.RUSAGE_SELF))
    stats_process[0] = new

    # Get RSS in bytes
    stats["memory_rss"] = new[1].ru_maxrss

    # Get CPU time in % of a single core, not % of all cores
    used_cpu_time = (new[1].ru_utime + new[1].ru_stime) - (
        old[1].ru_utime + old[1].ru_stime
    )
    if used_cpu_time == 0 or new[0] == old[0]:
        stats["cpu_average"] = 0
    else:
        stats["cpu_average"] = math.floor(used_cpu_time / (new[0] - old[0]) * 100)

    #
    # General statistics
    #

    store = hs.get_datastores().main
    common_metrics = await hs.get_common_usage_metrics_manager().get_metrics()

    stats["homeserver"] = hs.config.server.server_name
    stats["server_context"] = hs.config.server.server_context
    stats["timestamp"] = now
    stats["uptime_seconds"] = uptime
    version = sys.version_info
    stats["python_version"] = "{}.{}.{}".format(
        version.major, version.minor, version.micro
    )
    stats["total_users"] = await store.count_all_users()

    total_nonbridged_users = await store.count_nonbridged_users()
    stats["total_nonbridged_users"] = total_nonbridged_users

    daily_user_type_results = await store.count_daily_user_type()
    for name, count in daily_user_type_results.items():
        stats["daily_user_type_" + name] = count

    room_count = await store.get_room_count()
    stats["total_room_count"] = room_count

    stats["daily_active_users"] = common_metrics.daily_active_users
    stats["monthly_active_users"] = await store.count_monthly_users()
    daily_active_e2ee_rooms = await store.count_daily_active_e2ee_rooms()
    stats["daily_active_e2ee_rooms"] = daily_active_e2ee_rooms
    stats["daily_e2ee_messages"] = await store.count_daily_e2ee_messages()
    daily_sent_e2ee_messages = await store.count_daily_sent_e2ee_messages()
    stats["daily_sent_e2ee_messages"] = daily_sent_e2ee_messages
    stats["daily_active_rooms"] = await store.count_daily_active_rooms()
    stats["daily_messages"] = await store.count_daily_messages()
    daily_sent_messages = await store.count_daily_sent_messages()
    stats["daily_sent_messages"] = daily_sent_messages

    r30_results = await store.count_r30_users()
    for name, count in r30_results.items():
        stats["r30_users_" + name] = count

    r30v2_results = await store.count_r30v2_users()
    for name, count in r30v2_results.items():
        stats["r30v2_users_" + name] = count

    stats["cache_factor"] = hs.config.caches.global_factor
    stats["event_cache_size"] = hs.config.caches.event_cache_size

    #
    # Database version
    #

    # This only reports info about the *main* database.
    stats["database_engine"] = store.db_pool.engine.module.__name__
    stats["database_server_version"] = store.db_pool.engine.server_version

    #
    # Logging configuration
    #
    synapse_logger = logging.getLogger("synapse")
    log_level = synapse_logger.getEffectiveLevel()
    stats["log_level"] = logging.getLevelName(log_level)

    logger.info(
        "Reporting stats to %s: %s" % (hs.config.metrics.report_stats_endpoint, stats)
    )
    try:
        await hs.get_proxied_http_client().put_json(
            hs.config.metrics.report_stats_endpoint, stats
        )
    except Exception as e:
        logger.warning("Error reporting stats: %s", e)


def start_phone_stats_home(hs: "HomeServer") -> None:
    """
    Start the background tasks which report phone home stats.
    """
    clock = hs.get_clock()

    stats: JsonDict = {}

    def performance_stats_init() -> None:
        _stats_process.clear()
        _stats_process.append(
            (int(hs.get_clock().time()), resource.getrusage(resource.RUSAGE_SELF))
        )

    # Rather than update on per session basis, batch up the requests.
    # If you increase the loop period, the accuracy of user_daily_visits
    # table will decrease
    clock.looping_call(
        hs.get_datastores().main.generate_user_daily_visits, 5 * 60 * 1000
    )

    # monthly active user limiting functionality
    clock.looping_call(
        hs.get_datastores().main.reap_monthly_active_users, 1000 * 60 * 60
    )
    hs.get_datastores().main.reap_monthly_active_users()

    @wrap_as_background_process("generate_monthly_active_users")
    async def generate_monthly_active_users() -> None:
        current_mau_count = 0
        current_mau_count_by_service = {}
        reserved_users: Sized = ()
        store = hs.get_datastores().main
        if hs.config.server.limit_usage_by_mau or hs.config.server.mau_stats_only:
            current_mau_count = await store.get_monthly_active_count()
            current_mau_count_by_service = (
                await store.get_monthly_active_count_by_service()
            )
            reserved_users = await store.get_registered_reserved_users()
        current_mau_gauge.set(float(current_mau_count))

        for app_service, count in current_mau_count_by_service.items():
            current_mau_by_service_gauge.labels(app_service).set(float(count))

        registered_reserved_users_mau_gauge.set(float(len(reserved_users)))
        max_mau_gauge.set(float(hs.config.server.max_mau_value))

    if hs.config.server.limit_usage_by_mau or hs.config.server.mau_stats_only:
        generate_monthly_active_users()
        clock.looping_call(generate_monthly_active_users, 5 * 60 * 1000)
    # End of monthly active user settings

    if hs.config.metrics.report_stats:
        logger.info("Scheduling stats reporting for 3 hour intervals")
        clock.looping_call(phone_stats_home, 3 * 60 * 60 * 1000, hs, stats)

        # We need to defer this init for the cases that we daemonize
        # otherwise the process ID we get is that of the non-daemon process
        clock.call_later(0, performance_stats_init)

        # We wait 5 minutes to send the first set of stats as the server can
        # be quite busy the first few minutes
        clock.call_later(5 * 60, phone_stats_home, hs, stats)
