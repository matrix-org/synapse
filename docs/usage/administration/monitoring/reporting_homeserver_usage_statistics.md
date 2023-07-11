# Reporting Homeserver Usage Statistics

When generating your Synapse configuration file, you are asked whether you
would like to report usage statistics to Matrix.org. These statistics
provide the foundation a glimpse into the number of Synapse homeservers
participating in the network, as well as statistics such as the number of
rooms being created and messages being sent. This feature is sometimes
affectionately called "phone home" stats. Reporting
[is optional](../../configuration/config_documentation.md#report_stats)
and the reporting endpoint
[can be configured](../../configuration/config_documentation.md#report_stats_endpoint),
in case you would like to instead report statistics from a set of homeservers
to your own infrastructure.

This documentation aims to define the statistics available and the
homeserver configuration options that exist to tweak it.

## Available Statistics

The following statistics are sent to the configured reporting endpoint:

| Statistic Name             | Type   | Description                                                                                                                                                                                                                                                                                     |
|----------------------------|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `homeserver`               | string | The homeserver's server name.                                                                                                                                                                                                                                                                   |
| `memory_rss`               | int    | The memory usage of the process (in kilobytes on Unix-based systems, bytes on MacOS).                                                                                                                                                                                                           |
| `cpu_average`              | int    | CPU time in % of a single core (not % of all cores).                                                                                                                                                                                                                                            |              
| `server_context`           | string | An arbitrary string used to group statistics from a set of homeservers.                                                                                                                                                                                                                         |
| `timestamp`                | int    | The current time, represented as the number of seconds since the epoch.                                                                                                                                                                                                                         |                 
| `uptime_seconds`           | int    | The number of seconds since the homeserver was last started.                                                                                                                                                                                                                                    |
| `python_version`           | string | The Python version number in use (e.g "3.7.1"). Taken from `sys.version_info`.                                                                                                                                                                                                                  |
| `total_users`              | int    | The number of registered users on the homeserver.                                                                                                                                                                                                                                               |
| `total_nonbridged_users`   | int    | The number of users, excluding those created by an Application Service.                                                                                                                                                                                                                         |
| `daily_user_type_native`   | int    | The number of native users created in the last 24 hours.                                                                                                                                                                                                                                        |
| `daily_user_type_guest`    | int    | The number of guest users created in the last 24 hours.                                                                                                                                                                                                                                         |
| `daily_user_type_bridged`  | int    | The number of users created by Application Services in the last 24 hours.                                                                                                                                                                                                                       |
| `total_room_count`         | int    | The total number of rooms present on the homeserver.                                                                                                                                                                                                                                            |
| `daily_active_users`       | int    | The number of unique users[^1] that have used the homeserver in the last 24 hours.                                                                                                                                                                                                              |
| `monthly_active_users`     | int    | The number of unique users[^1] that have used the homeserver in the last 30 days.                                                                                                                                                                                                               |
| `daily_active_rooms`       | int    | The number of rooms that have had a (state) event with the type `m.room.message` sent in them in the last 24 hours.                                                                                                                                                                             |
| `daily_active_e2ee_rooms`  | int    | The number of rooms that have had a (state) event with the type `m.room.encrypted` sent in them in the last 24 hours.                                                                                                                                                                           |
| `daily_messages`           | int    | The number of (state) events with the type `m.room.message` seen in the last 24 hours.                                                                                                                                                                                                          |
| `daily_e2ee_messages`      | int    | The number of (state) events with the type `m.room.encrypted` seen in the last 24 hours.                                                                                                                                                                                                        |
| `daily_sent_messages`      | int    | The number of (state) events sent by a local user with the type `m.room.message` seen in the last 24 hours.                                                                                                                                                                                     |
| `daily_sent_e2ee_messages` | int    | The number of (state) events sent by a local user with the type `m.room.encrypted` seen in the last 24 hours.                                                                                                                                                                                   |
| `r30v2_users_all`          | int    | The number of 30 day retained users, with a revised algorithm. Defined as users that appear more than once in the past 60 days, and have more than 30 days between the most and least recent appearances in the past 60 days. Includes clients that do not fit into the below r30 client types. |
| `r30v2_users_android`      | int    | The number of 30 day retained users, as defined above. Filtered only to clients with ("riot" or "element") and "android" (case-insensitive) in the user agent string.                                                                                                                           |
| `r30v2_users_ios`          | int    | The number of 30 day retained users, as defined above. Filtered only to clients with ("riot" or "element") and "ios" (case-insensitive) in the user agent string.                                                                                                                               |
| `r30v2_users_electron`     | int    | The number of 30 day retained users, as defined above. Filtered only to clients with ("riot" or "element") and "electron" (case-insensitive) in the user agent string.                                                                                                                          |
| `r30v2_users_web`          | int    | The number of 30 day retained users, as defined above. Filtered only to clients with "mozilla" or "gecko" (case-insensitive) in the user agent string.                                                                                                                                          |
| `cache_factor`             | int    | The configured [`global factor`](../../configuration/config_documentation.md#caching) value for caching.                                                                                                                                                                                        |
| `event_cache_size`         | int    | The configured [`event_cache_size`](../../configuration/config_documentation.md#caching) value for caching.                                                                                                                                                                                     |
| `database_engine`          | string | The database engine that is in use. Either "psycopg2" meaning PostgreSQL is in use, or "sqlite3" for SQLite3.                                                                                                                                                                                   |
| `database_server_version` | string | The version of the database server. Examples being "10.10" for PostgreSQL server version 10.0, and "3.38.5" for SQLite 3.38.5 installed on the system.                                                                                                                                          |
| `log_level` | string | The log level in use. Examples are "INFO", "WARNING", "ERROR", "DEBUG", etc.                                                                                                                                                                                                                    |


[^1]: Native matrix users and guests are always counted. If the
[`track_puppeted_user_ips`](../../configuration/config_documentation.md#track_puppeted_user_ips)
option is set to `true`, "puppeted" users (users that an Application Service have performed
[an action on behalf of](https://spec.matrix.org/v1.3/application-service-api/#identity-assertion))
will also be counted. Note that an Application Service can "puppet" any user in their
[user namespace](https://spec.matrix.org/v1.3/application-service-api/#registration),
not only users that the Application Service has created. If this happens, the Application Service
will additionally be counted as a user (irrespective of `track_puppeted_user_ips`).

## Using a Custom Statistics Collection Server

If statistics reporting is enabled, the endpoint that Synapse sends metrics to is configured by the
[`report_stats_endpoint`](../../configuration/config_documentation.md#report_stats_endpoint) config
option. By default, statistics are sent to Matrix.org.

If you would like to set up your own statistics collection server and send metrics there, you may
consider using one of the following known implementations:

* [Matrix.org's Panopticon](https://github.com/matrix-org/panopticon)
* [Famedly's Barad-dûr](https://gitlab.com/famedly/infra/services/barad-dur)
