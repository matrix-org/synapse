# How to monitor Synapse metrics using Prometheus

1.  Install Prometheus:

    Follow instructions at
    <http://prometheus.io/docs/introduction/install/>

1.  Enable Synapse metrics:

    There are two methods of enabling metrics in Synapse.

    The first serves the metrics as a part of the usual web server and
    can be enabled by adding the \"metrics\" resource to the existing
    listener as such:

    ```yaml
      resources:
        - names:
          - client
          - metrics
    ```

    This provides a simple way of adding metrics to your Synapse
    installation, and serves under `/_synapse/metrics`. If you do not
    wish your metrics be publicly exposed, you will need to either
    filter it out at your load balancer, or use the second method.

    The second method runs the metrics server on a different port, in a
    different thread to Synapse. This can make it more resilient to
    heavy load meaning metrics cannot be retrieved, and can be exposed
    to just internal networks easier. The served metrics are available
    over HTTP only, and will be available at `/_synapse/metrics`.

    Add a new listener to homeserver.yaml:

    ```yaml
      listeners:
        - type: metrics
          port: 9000
          bind_addresses:
            - '0.0.0.0'
    ```

    For both options, you will need to ensure that `enable_metrics` is
    set to `True`.

1.  Restart Synapse.

1.  Add a Prometheus target for Synapse.

    It needs to set the `metrics_path` to a non-default value (under
    `scrape_configs`):

    ```yaml
      - job_name: "synapse"
        scrape_interval: 15s
        metrics_path: "/_synapse/metrics"
        static_configs:
          - targets: ["my.server.here:port"]
    ```

    where `my.server.here` is the IP address of Synapse, and `port` is
    the listener port configured with the `metrics` resource.

    If your prometheus is older than 1.5.2, you will need to replace
    `static_configs` in the above with `target_groups`.

1.  Restart Prometheus.

1.  Consider using the [grafana dashboard](https://github.com/matrix-org/synapse/tree/master/contrib/grafana/)
    and required [recording rules](https://github.com/matrix-org/synapse/tree/master/contrib/prometheus/) 

## Monitoring workers

To monitor a Synapse installation using
[workers](https://github.com/matrix-org/synapse/blob/master/docs/workers.md),
every worker needs to be monitored independently, in addition to
the main homeserver process. This is because workers don't send
their metrics to the main homeserver process, but expose them
directly (if they are configured to do so).

To allow collecting metrics from a worker, you need to add a
`metrics` listener to its configuration, by adding the following
under `worker_listeners`:

```yaml
  - type: metrics
    bind_address: ''
    port: 9101
```

The `bind_address` and `port` parameters should be set so that
the resulting listener can be reached by prometheus, and they
don't clash with an existing worker.
With this example, the worker's metrics would then be available
on `http://127.0.0.1:9101`.

Example Prometheus target for Synapse with workers:

```yaml
  - job_name: "synapse"
    scrape_interval: 15s
    metrics_path: "/_synapse/metrics"
    static_configs:
      - targets: ["my.server.here:port"]
        labels:
          instance: "my.server"
          job: "master"
          index: 1
      - targets: ["my.workerserver.here:port"]
        labels:
          instance: "my.server"
          job: "generic_worker"
          index: 1
      - targets: ["my.workerserver.here:port"]
        labels:
          instance: "my.server"
          job: "generic_worker"
          index: 2
      - targets: ["my.workerserver.here:port"]
        labels:
          instance: "my.server"
          job: "media_repository"
          index: 1
```

Labels (`instance`, `job`, `index`) can be defined as anything.
The labels are used to group graphs in grafana.

## Renaming of metrics & deprecation of old names in 1.2

Synapse 1.2 updates the Prometheus metrics to match the naming
convention of the upstream `prometheus_client`. The old names are
considered deprecated and will be removed in a future version of
Synapse.

| New Name                                                                     | Old Name                                                               |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| python_gc_objects_collected_total                                            | python_gc_objects_collected                                            |
| python_gc_objects_uncollectable_total                                        | python_gc_objects_uncollectable                                        |
| python_gc_collections_total                                                  | python_gc_collections                                                  |
| process_cpu_seconds_total                                                    | process_cpu_seconds                                                    |
| synapse_federation_client_sent_transactions_total                            | synapse_federation_client_sent_transactions                            |
| synapse_federation_client_events_processed_total                             | synapse_federation_client_events_processed                             |
| synapse_event_processing_loop_count_total                                    | synapse_event_processing_loop_count                                    |
| synapse_event_processing_loop_room_count_total                               | synapse_event_processing_loop_room_count                               |
| synapse_util_metrics_block_count_total                                       | synapse_util_metrics_block_count                                       |
| synapse_util_metrics_block_time_seconds_total                                | synapse_util_metrics_block_time_seconds                                |
| synapse_util_metrics_block_ru_utime_seconds_total                            | synapse_util_metrics_block_ru_utime_seconds                            |
| synapse_util_metrics_block_ru_stime_seconds_total                            | synapse_util_metrics_block_ru_stime_seconds                            |
| synapse_util_metrics_block_db_txn_count_total                                | synapse_util_metrics_block_db_txn_count                                |
| synapse_util_metrics_block_db_txn_duration_seconds_total                     | synapse_util_metrics_block_db_txn_duration_seconds                     |
| synapse_util_metrics_block_db_sched_duration_seconds_total                   | synapse_util_metrics_block_db_sched_duration_seconds                   |
| synapse_background_process_start_count_total                                 | synapse_background_process_start_count                                 |
| synapse_background_process_ru_utime_seconds_total                            | synapse_background_process_ru_utime_seconds                            |
| synapse_background_process_ru_stime_seconds_total                            | synapse_background_process_ru_stime_seconds                            |
| synapse_background_process_db_txn_count_total                                | synapse_background_process_db_txn_count                                |
| synapse_background_process_db_txn_duration_seconds_total                     | synapse_background_process_db_txn_duration_seconds                     |
| synapse_background_process_db_sched_duration_seconds_total                   | synapse_background_process_db_sched_duration_seconds                   |
| synapse_storage_events_persisted_events_total                                | synapse_storage_events_persisted_events                                |
| synapse_storage_events_persisted_events_sep_total                            | synapse_storage_events_persisted_events_sep                            |
| synapse_storage_events_state_delta_total                                     | synapse_storage_events_state_delta                                     |
| synapse_storage_events_state_delta_single_event_total                        | synapse_storage_events_state_delta_single_event                        |
| synapse_storage_events_state_delta_reuse_delta_total                         | synapse_storage_events_state_delta_reuse_delta                         |
| synapse_federation_server_received_pdus_total                                | synapse_federation_server_received_pdus                                |
| synapse_federation_server_received_edus_total                                | synapse_federation_server_received_edus                                |
| synapse_handler_presence_notified_presence_total                             | synapse_handler_presence_notified_presence                             |
| synapse_handler_presence_federation_presence_out_total                       | synapse_handler_presence_federation_presence_out                       |
| synapse_handler_presence_presence_updates_total                              | synapse_handler_presence_presence_updates                              |
| synapse_handler_presence_timers_fired_total                                  | synapse_handler_presence_timers_fired                                  |
| synapse_handler_presence_federation_presence_total                           | synapse_handler_presence_federation_presence                           |
| synapse_handler_presence_bump_active_time_total                              | synapse_handler_presence_bump_active_time                              |
| synapse_federation_client_sent_edus_total                                    | synapse_federation_client_sent_edus                                    |
| synapse_federation_client_sent_pdu_destinations_count_total                  | synapse_federation_client_sent_pdu_destinations:count                  |
| synapse_federation_client_sent_pdu_destinations_total                        | synapse_federation_client_sent_pdu_destinations:total                  |
| synapse_handlers_appservice_events_processed_total                           | synapse_handlers_appservice_events_processed                           |
| synapse_notifier_notified_events_total                                       | synapse_notifier_notified_events                                       |
| synapse_push_bulk_push_rule_evaluator_push_rules_invalidation_counter_total  | synapse_push_bulk_push_rule_evaluator_push_rules_invalidation_counter  |
| synapse_push_bulk_push_rule_evaluator_push_rules_state_size_counter_total    | synapse_push_bulk_push_rule_evaluator_push_rules_state_size_counter    |
| synapse_http_httppusher_http_pushes_processed_total                          | synapse_http_httppusher_http_pushes_processed                          |
| synapse_http_httppusher_http_pushes_failed_total                             | synapse_http_httppusher_http_pushes_failed                             |
| synapse_http_httppusher_badge_updates_processed_total                        | synapse_http_httppusher_badge_updates_processed                        |
| synapse_http_httppusher_badge_updates_failed_total                           | synapse_http_httppusher_badge_updates_failed                           |

Removal of deprecated metrics & time based counters becoming histograms in 0.31.0
---------------------------------------------------------------------------------

The duplicated metrics deprecated in Synapse 0.27.0 have been removed.

All time duration-based metrics have been changed to be seconds. This
affects:

| msec -> sec metrics                    |
| -------------------------------------- |
| python_gc_time                         |
| python_twisted_reactor_tick_time       |
| synapse_storage_query_time             |
| synapse_storage_schedule_time          |
| synapse_storage_transaction_time       |

Several metrics have been changed to be histograms, which sort entries
into buckets and allow better analysis. The following metrics are now
histograms:

| Altered metrics                                  |
| ------------------------------------------------ |
| python_gc_time                                   |
| python_twisted_reactor_pending_calls             |
| python_twisted_reactor_tick_time                 |
| synapse_http_server_response_time_seconds        |
| synapse_storage_query_time                       |
| synapse_storage_schedule_time                    |
| synapse_storage_transaction_time                 |

Block and response metrics renamed for 0.27.0
---------------------------------------------

Synapse 0.27.0 begins the process of rationalising the duplicate
`*:count` metrics reported for the resource tracking for code blocks and
HTTP requests.

At the same time, the corresponding `*:total` metrics are being renamed,
as the `:total` suffix no longer makes sense in the absence of a
corresponding `:count` metric.

To enable a graceful migration path, this release just adds new names
for the metrics being renamed. A future release will remove the old
ones.

The following table shows the new metrics, and the old metrics which
they are replacing.

| New name                                                      | Old name                                                   |
| ------------------------------------------------------------- | ---------------------------------------------------------- |
| synapse_util_metrics_block_count                              | synapse_util_metrics_block_timer:count                     |
| synapse_util_metrics_block_count                              | synapse_util_metrics_block_ru_utime:count                  |
| synapse_util_metrics_block_count                              | synapse_util_metrics_block_ru_stime:count                  |
| synapse_util_metrics_block_count                              | synapse_util_metrics_block_db_txn_count:count              |
| synapse_util_metrics_block_count                              | synapse_util_metrics_block_db_txn_duration:count           |
| synapse_util_metrics_block_time_seconds                       | synapse_util_metrics_block_timer:total                     |
| synapse_util_metrics_block_ru_utime_seconds                   | synapse_util_metrics_block_ru_utime:total                  |
| synapse_util_metrics_block_ru_stime_seconds                   | synapse_util_metrics_block_ru_stime:total                  |
| synapse_util_metrics_block_db_txn_count                       | synapse_util_metrics_block_db_txn_count:total              |
| synapse_util_metrics_block_db_txn_duration_seconds            | synapse_util_metrics_block_db_txn_duration:total           |
| synapse_http_server_response_count                            | synapse_http_server_requests                               |
| synapse_http_server_response_count                            | synapse_http_server_response_time:count                    |
| synapse_http_server_response_count                            | synapse_http_server_response_ru_utime:count                |
| synapse_http_server_response_count                            | synapse_http_server_response_ru_stime:count                |
| synapse_http_server_response_count                            | synapse_http_server_response_db_txn_count:count            |
| synapse_http_server_response_count                            | synapse_http_server_response_db_txn_duration:count         |
| synapse_http_server_response_time_seconds                     | synapse_http_server_response_time:total                    |
| synapse_http_server_response_ru_utime_seconds                 | synapse_http_server_response_ru_utime:total                |
| synapse_http_server_response_ru_stime_seconds                 | synapse_http_server_response_ru_stime:total                |
| synapse_http_server_response_db_txn_count                     | synapse_http_server_response_db_txn_count:total            |
| synapse_http_server_response_db_txn_duration_seconds          | synapse_http_server_response_db_txn_duration:total         |

Standard Metric Names
---------------------

As of synapse version 0.18.2, the format of the process-wide metrics has
been changed to fit prometheus standard naming conventions. Additionally
the units have been changed to seconds, from miliseconds.

| New name                                 | Old name                          |
| ---------------------------------------- | --------------------------------- |
| process_cpu_user_seconds_total           | process_resource_utime / 1000     |
| process_cpu_system_seconds_total         | process_resource_stime / 1000     |
| process_open_fds (no \'type\' label)     | process_fds                       |

The python-specific counts of garbage collector performance have been
renamed.

| New name                         | Old name                   |
| -------------------------------- | -------------------------- |
| python_gc_time                   | reactor_gc_time            |
| python_gc_unreachable_total      | reactor_gc_unreachable     |
| python_gc_counts                 | reactor_gc_counts          |

The twisted-specific reactor metrics have been renamed.

| New name                               | Old name                |
| -------------------------------------- | ----------------------- |
| python_twisted_reactor_pending_calls   | reactor_pending_calls   |
| python_twisted_reactor_tick_time       | reactor_tick_time       |
