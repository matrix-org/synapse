### Using synctl with workers

If you want to use `synctl` to manage your synapse processes, you will need to
create an an additional configuration file for the main synapse process. That
configuration should look like this:

```yaml
worker_app: synapse.app.homeserver
```

Additionally, each worker app must be configured with the name of a "pid file",
to which it will write its process ID when it starts. For example, for a
synchrotron, you might write:

```yaml
worker_pid_file: /home/matrix/synapse/worker1.pid
```

Finally, to actually run your worker-based synapse, you must pass synctl the `-a`
commandline option to tell it to operate on all the worker configurations found
in the given directory, e.g.:

```sh
synctl -a $CONFIG/workers start
```

Currently one should always restart all workers when restarting or upgrading
synapse, unless you explicitly know it's safe not to.  For instance, restarting
synapse without restarting all the synchrotrons may result in broken typing
notifications.

To manipulate a specific worker, you pass the -w option to synctl:

```sh
synctl -w $CONFIG/workers/worker1.yaml restart
```
