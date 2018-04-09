How to monitor Synapse metrics using Prometheus
===============================================

1. Install prometheus:

   Follow instructions at http://prometheus.io/docs/introduction/install/

2. Enable synapse metrics:

   Simply setting a (local) port number will enable it. Pick a port.
   prometheus itself defaults to 9090, so starting just above that for
   locally monitored services seems reasonable. E.g. 9092:

   Add to homeserver.yaml::

     metrics_port: 9092

   Also ensure that ``enable_metrics`` is set to ``True``.

   Restart synapse.

3. Add a prometheus target for synapse.

   It needs to set the ``metrics_path`` to a non-default value (under ``scrape_configs``)::

    - job_name: "synapse"
      metrics_path: "/_synapse/metrics"
      static_configs:
        - targets: ["my.server.here:9092"]

   If your prometheus is older than 1.5.2, you will need to replace
   ``static_configs`` in the above with ``target_groups``.

   Restart prometheus.


Block and response metrics renamed for 0.27.0
---------------------------------------------

Synapse 0.27.0 begins the process of rationalising the duplicate ``*:count``
metrics reported for the resource tracking for code blocks and HTTP requests.

At the same time, the corresponding ``*:total`` metrics are being renamed, as
the ``:total`` suffix no longer makes sense in the absence of a corresponding
``:count`` metric.

To enable a graceful migration path, this release just adds new names for the
metrics being renamed. A future release will remove the old ones.

The following table shows the new metrics, and the old metrics which they are
replacing.

==================================================== ===================================================
New name                                             Old name
==================================================== ===================================================
synapse_util_metrics_block_count                     synapse_util_metrics_block_timer:count
synapse_util_metrics_block_count                     synapse_util_metrics_block_ru_utime:count
synapse_util_metrics_block_count                     synapse_util_metrics_block_ru_stime:count
synapse_util_metrics_block_count                     synapse_util_metrics_block_db_txn_count:count
synapse_util_metrics_block_count                     synapse_util_metrics_block_db_txn_duration:count

synapse_util_metrics_block_time_seconds              synapse_util_metrics_block_timer:total
synapse_util_metrics_block_ru_utime_seconds          synapse_util_metrics_block_ru_utime:total
synapse_util_metrics_block_ru_stime_seconds          synapse_util_metrics_block_ru_stime:total
synapse_util_metrics_block_db_txn_count              synapse_util_metrics_block_db_txn_count:total
synapse_util_metrics_block_db_txn_duration_seconds   synapse_util_metrics_block_db_txn_duration:total

synapse_http_server_response_count                   synapse_http_server_requests
synapse_http_server_response_count                   synapse_http_server_response_time:count
synapse_http_server_response_count                   synapse_http_server_response_ru_utime:count
synapse_http_server_response_count                   synapse_http_server_response_ru_stime:count
synapse_http_server_response_count                   synapse_http_server_response_db_txn_count:count
synapse_http_server_response_count                   synapse_http_server_response_db_txn_duration:count

synapse_http_server_response_time_seconds            synapse_http_server_response_time:total
synapse_http_server_response_ru_utime_seconds        synapse_http_server_response_ru_utime:total
synapse_http_server_response_ru_stime_seconds        synapse_http_server_response_ru_stime:total
synapse_http_server_response_db_txn_count            synapse_http_server_response_db_txn_count:total
synapse_http_server_response_db_txn_duration_seconds synapse_http_server_response_db_txn_duration:total
==================================================== ===================================================


Standard Metric Names
---------------------

As of synapse version 0.18.2, the format of the process-wide metrics has been
changed to fit prometheus standard naming conventions. Additionally the units
have been changed to seconds, from miliseconds.

================================== =============================
New name                           Old name
================================== =============================
process_cpu_user_seconds_total     process_resource_utime / 1000
process_cpu_system_seconds_total   process_resource_stime / 1000
process_open_fds (no 'type' label) process_fds
================================== =============================

The python-specific counts of garbage collector performance have been renamed.

=========================== ======================
New name                    Old name
=========================== ======================
python_gc_time              reactor_gc_time
python_gc_unreachable_total reactor_gc_unreachable
python_gc_counts            reactor_gc_counts
=========================== ======================

The twisted-specific reactor metrics have been renamed.

==================================== =====================
New name                             Old name
==================================== =====================
python_twisted_reactor_pending_calls reactor_pending_calls
python_twisted_reactor_tick_time     reactor_tick_time
==================================== =====================
