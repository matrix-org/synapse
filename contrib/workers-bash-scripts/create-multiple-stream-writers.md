# Creating multiple stream writers with a bash script

This script creates multiple [stream writer](https://github.com/matrix-org/synapse/blob/develop/docs/workers.md#stream-writers) workers.

Stream writers require both replication and HTTP listeners.

It also prints out the example lines for Synapse main configuration file.

Remember to route necessary endpoints directly to a worker associated with it.

If you run the script as-is, it will create workers with the replication listener starting from port 8034 and another, "safe" listener starting from 8044. If you don't need all of stream writers listed in the script, just remove them from the ```STREAM_WRITERS``` array.

```sh
#!/bin/bash

# Start with these replication and http ports.
# The script loop starts with the exact port and then increments it by one.
REP_START_PORT=8034
HTTP_START_PORT=8044

# Stream writer workers to generate. Feel free to add or remove them as you wish.
# Event persister ("events") isn't included here as it does not require its
# own HTTP listener.

STREAM_WRITERS+=( "presence" "typing" "receipts" "to_device" "account_data" )

NUM_WRITERS=$(expr ${#STREAM_WRITERS[@]} - 1)

i=0

while [ $i -le "$NUM_WRITERS" ]
do
cat << EOF > ${STREAM_WRITERS[$i]}_stream_writer.yaml
worker_app: synapse.app.generic_worker
worker_name: ${STREAM_WRITERS[$i]}_stream_writer

# The replication listener on the main synapse process.
worker_replication_host: 127.0.0.1
worker_replication_http_port: 9093

worker_listeners:
  - type: http
    port: $(expr $REP_START_PORT + $i)
    resources:
      - names: [replication]

  - type: http
    port: $(expr $HTTP_START_PORT + $i)
    resources:
      - names: [client]

worker_log_config: /etc/matrix-synapse/stream-writer-log.yaml
EOF
HOMESERVER_YAML_INSTANCE_MAP+=$"  ${STREAM_WRITERS[$i]}_stream_writer:
    host: 127.0.0.1
    port: $(expr $REP_START_PORT + $i)
"

HOMESERVER_YAML_STREAM_WRITERS+=$"  ${STREAM_WRITERS[$i]}: ${STREAM_WRITERS[$i]}_stream_writer
"

((i++))
done

echo "# Add these lines to your homeserver.yaml."
echo "# Don't forget to configure your reverse proxy and"
echo "# necessary endpoints to their respective worker."
echo ""
echo "# See https://github.com/matrix-org/synapse/blob/develop/docs/workers.md"
echo "# for more information"
echo ""
echo "# Remember: Under NO circumstances should the replication"
echo "# listener be exposed to the public internet;"
echo "# it has no authentication and is unencrypted."
echo ""
echo "instance_map:"
echo "$HOMESERVER_YAML_INSTANCE_MAP"
echo "stream_writers:"
echo "$HOMESERVER_YAML_STREAM_WRITERS"
```
