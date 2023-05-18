# Creating multiple stream writers with a bash script

This script creates multiple [stream writer](https://github.com/matrix-org/synapse/blob/develop/docs/workers.md#stream-writers) workers.

Stream writers require both replication and HTTP listeners.

It also prints out the example lines for Synapse main configuration file.

Remember to route necessary endpoints directly to a worker associated with it.

If you run the script as-is, it will create workers with the replication listener starting from port 8034 and another, regular http listener starting from 8044. If you don't need all of the stream writers listed in the script, just remove them from the ```STREAM_WRITERS``` array. 

Hint: Note that `worker_pid_file` is required if `worker_daemonize` is `true`. Uncomment and/or modify the line if needed.

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

NUM_WRITERS=$(expr ${#STREAM_WRITERS[@]})

i=0

while [ $i -lt "$NUM_WRITERS" ]
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
    x_forwarded: true
    resources:
      - names: [client]

#worker_pid_file: DATADIR/${STREAM_WRITERS[$i]}.pid
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

cat << EXAMPLECONFIG
# Add these lines to your homeserver.yaml.
# Don't forget to configure your reverse proxy and
# necessary endpoints to their respective worker.

# See https://github.com/matrix-org/synapse/blob/develop/docs/workers.md
# for more information.

# Remember: Under NO circumstances should the replication
# listener be exposed to the public internet;
# it has no authentication and is unencrypted.

instance_map:
$HOMESERVER_YAML_INSTANCE_MAP
stream_writers:
$HOMESERVER_YAML_STREAM_WRITERS
EXAMPLECONFIG
```

Copy the code above save it to a file ```create_stream_writers.sh``` (for example).

Make the script executable by running ```chmod +x create_stream_writers.sh```.

## Run the script to create workers and print out a sample configuration

Simply run the script to create YAML files in the current folder and print out the required configuration for ```homeserver.yaml```.

```console
$ ./create_stream_writers.sh
```
You should receive an output similar to the following:
```console
# Add these lines to your homeserver.yaml.
# Don't forget to configure your reverse proxy and
# necessary endpoints to their respective worker.

# See https://github.com/matrix-org/synapse/blob/develop/docs/workers.md
# for more information

# Remember: Under NO circumstances should the replication
# listener be exposed to the public internet;
# it has no authentication and is unencrypted.

instance_map:
  presence_stream_writer:
    host: 127.0.0.1
    port: 8034
  typing_stream_writer:
    host: 127.0.0.1
    port: 8035
  receipts_stream_writer:
    host: 127.0.0.1
    port: 8036
  to_device_stream_writer:
    host: 127.0.0.1
    port: 8037
  account_data_stream_writer:
    host: 127.0.0.1
    port: 8038

stream_writers:
  presence: presence_stream_writer
  typing: typing_stream_writer
  receipts: receipts_stream_writer
  to_device: to_device_stream_writer
  account_data: account_data_stream_writer
```

Simply copy-and-paste the output to an appropriate place in your Synapse main configuration file.

## Write directly to Synapse configuration file

You could also write the output directly to homeserver main configuration file. **This, however, is not recommended** as even a small typo (such as replacing >> with >) can erase the entire ```homeserver.yaml```. 

If you do this, back up your original configuration file first:

```console
# Back up homeserver.yaml first
cp /etc/matrix-synapse/homeserver.yaml /etc/matrix-synapse/homeserver.yaml.bak 

# Create workers and write output to your homeserver.yaml
./create_stream_writers.sh >> /etc/matrix-synapse/homeserver.yaml 
```
