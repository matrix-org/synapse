How to monitor Synapse metrics using Prometheus
===============================================

1. Install Prometheus:

   Follow instructions at http://prometheus.io/docs/introduction/install/

2. Enable Synapse metrics:

   There are two methods of enabling metrics in Synapse.

   The first serves the metrics as a part of the usual web server and can be
   enabled by adding the "metrics" resource to the existing listener as such::

     resources:
       - names:
         - client
         - metrics

   This provides a simple way of adding metrics to your Synapse installation,
   and serves under ``/_synapse/metrics``. If you do not wish your metrics be
   publicly exposed, you will need to either filter it out at your load
   balancer, or use the second method.

   The second method runs the metrics server on a different port, in a
   different thread to Synapse. This can make it more resilient to heavy load
   meaning metrics cannot be retrieved, and can be exposed to just internal
   networks easier. The served metrics are available over HTTP only, and will
   be available at ``/``.

   Add a new listener to homeserver.yaml::

     listeners:
       - type: metrics
         port: 9000
         bind_addresses:
           - '0.0.0.0'

   For both options, you will need to ensure that ``enable_metrics`` is set to
   ``True``.

   Restart Synapse.

3. Add a Prometheus target for Synapse.

   It needs to set the ``metrics_path`` to a non-default value (under ``scrape_configs``)::

    - job_name: "synapse"
      metrics_path: "/_synapse/metrics"
      static_configs:
        - targets: ["my.server.here:port"]

   where ``my.server.here`` is the IP address of Synapse, and ``port`` is the listener port
   configured with the ``metrics`` resource.

   If your prometheus is older than 1.5.2, you will need to replace
   ``static_configs`` in the above with ``target_groups``.

   Restart Prometheus.


Removal of deprecated metrics & time based counters becoming histograms in 0.31.0
---------------------------------------------------------------------------------

The duplicated metrics deprecated in Synapse 0.27.0 have been removed.

All time duration-based metrics have been changed to be seconds. This affects:

+----------------------------------+
| msec -> sec metrics              |
+==================================+
| python_gc_time                   |
+----------------------------------+
| python_twisted_reactor_tick_time |
+----------------------------------+
| synapse_storage_query_time       |
+----------------------------------+
| synapse_storage_schedule_time    |
+----------------------------------+
| synapse_storage_transaction_time |
+----------------------------------+

Several metrics have been changed to be histograms, which sort entries into
buckets and allow better analysis. The following metrics are now histograms:

+-------------------------------------------+
| Altered metrics                           |
+===========================================+
| python_gc_time                            |
+-------------------------------------------+
| python_twisted_reactor_pending_calls      |
+-------------------------------------------+
| python_twisted_reactor_tick_time          |
+-------------------------------------------+
| synapse_http_server_response_time_seconds |
+-------------------------------------------+
| synapse_storage_query_time                |
+-------------------------------------------+
| synapse_storage_schedule_time             |
+-------------------------------------------+
| synapse_storage_transaction_time          |
+-------------------------------------------+


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
