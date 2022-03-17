# workers_setup

This gives you a **development-grade** installation of workerised Synapse.

DO NOT USE ME IN PRODUCTION.

## Known defects

* Non-generic workers aren't set up properly with their worker type.
* I haven't checked the routes that well; they are probably wrong.


## Requirements from you:

* Redis on default port (unauthenticated)
  ```
  # You need Redis. On Ubuntu, this gets you what you need running on the right port:
  apt install redis-server redis-tools
  ```
* Postgres on default port, using UNIX sockets for authentication.
  This means you want your normal user account to have a corresponding Postgres account,
  and let Postgres authenticate you automatically.
  On Ubuntu, this just means you need to `createuser <your Linux account name>`.
  You need a database with the same name as your server_name (I used `syn7`).
  It should be owned by your user; see `createdb` to do that properly (and don't
  forget to follow the Synapse instructions to use a C locale!)
  Typing `psql syn7` should just work once your database is ready.
  (If your UNIX socket is not numbered 5432, you might have to add `port: 5433`
  to the config. Somehow I messed up my Postgres installation ages ago that it
  chose port 5433 rather than the default 5432...)
* Virtualenv with Synapse (don't forget: `[postgres,redis]`)
* You'll need a bog standard Caddy binary (as the reverse proxy / router).
  The website offers pre-built static binaries.
* (Optional): If you want to federate, you can set up TLS yourself afterwards.
  I haven't bothered so far.


## Run the script

```
# python scripts-dev/workers_setup.py (path to server dir) (server name)
python scripts-dev/workers_setup.py ../servers/syn7_auto syn7
```


## Launching the homeserver

```
cd syn7_auto
/path/to/synapse/.venv/bin/synctl start homeserver.yaml -a workers
/path/to/caddy run
```


## Stopping the homeserver

```
# ^C to stop Caddy
/path/to/synapse/.venv/bin/synctl stop homeserver.yaml -a workers
```

