# Creating multiple generic workers with a bash script

Setting up multiple worker configuration files manually can be time-consuming.
You can alternatively create multiple worker configuration files with a simple `bash` script. For example:

```sh
#!/bin/bash
for i in {1..5}
do
cat << EOF > generic_worker$i.yaml
worker_app: synapse.app.generic_worker
worker_name: generic_worker$i

# The replication listener on the main synapse process.
worker_replication_host: 127.0.0.1
worker_replication_http_port: 9093

worker_listeners:
  - type: http
    port: 808$i
    x_forwarded: true
    resources:
      - names: [client, federation]

worker_log_config: /etc/matrix-synapse/generic-worker-log.yaml
#worker_pid_file: DATADIR/generic_worker$i.pid
EOF
done
```

This would create five generic workers with a unique `worker_name` field in each file and listening on ports 8081-8085.

Customise the script to your needs. Note that `worker_pid_file` is required if `worker_daemonize` is `true`. Uncomment and/or modify the line if needed.
