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

Standard Metric Names
---------------------

As of synapse version 0.18.2, the format of the process-wide metrics has been
changed to fit prometheus standard naming conventions. Additionally the units
have been changed to seconds, from miliseconds.

================================== =============================
New name                           Old name
---------------------------------- -----------------------------
process_cpu_user_seconds_total     process_resource_utime / 1000
process_cpu_system_seconds_total   process_resource_stime / 1000
process_open_fds (no 'type' label) process_fds
================================== =============================

The python-specific counts of garbage collector performance have been renamed.

=========================== ======================
New name                    Old name
--------------------------- ----------------------
python_gc_time              reactor_gc_time      
python_gc_unreachable_total reactor_gc_unreachable
python_gc_counts            reactor_gc_counts
=========================== ======================

The twisted-specific reactor metrics have been renamed.

==================================== =====================
New name                             Old name
------------------------------------ ---------------------
python_twisted_reactor_pending_calls reactor_pending_calls
python_twisted_reactor_tick_time     reactor_tick_time
==================================== =====================
