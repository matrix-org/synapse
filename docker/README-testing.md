# Running tests against a dockerised Synapse

It's possible to run integration tests against Synapse
using [Complement](https://github.com/matrix-org/complement). Complement is a Matrix Spec
compliance test suite for homeservers, and supports any homeserver docker image configured
to listen on ports 8008/8448. This document contains instructions for building Synapse
docker images that can be run inside Complement for testing purposes.

Note that running Synapse's unit tests from within the docker image is not supported.

## Testing with SQLite and single-process Synapse

> Note that `scripts-dev/complement.sh` is a script that will automatically build 
> and run an SQLite-based, single-process of Synapse against Complement.

The instructions below will set up Complement testing for a single-process, 
SQLite-based Synapse deployment.

Start by building the base Synapse docker image. If you wish to run tests with the latest
release of Synapse, instead of your current checkout, you can skip this step. From the
root of the repository:

```sh
docker build -t matrixdotorg/synapse -f docker/Dockerfile .
```

This will build an image with the tag `matrixdotorg/synapse`.

Next, build the Synapse image for Complement. You will need a local checkout 
of Complement. Change to the root of your Complement checkout and run:

```sh
docker build -t complement-synapse -f "dockerfiles/Synapse.Dockerfile" dockerfiles
```

This will build an image with the tag `complement-synapse`, which can be handed to 
Complement for testing via the `COMPLEMENT_BASE_IMAGE` environment variable. Refer to 
[Complement's documentation](https://github.com/matrix-org/complement/#running) for 
how to run the tests, as well as the various available command line flags.

## Testing with PostgreSQL and single or multi-process Synapse

The above docker image only supports running Synapse with SQLite and in a 
single-process topology. The following instructions are used to build a Synapse image for 
Complement that supports either single or multi-process topology with a PostgreSQL 
database backend.

As with the single-process image, build the base Synapse docker image. If you wish to run
tests with the latest release of Synapse, instead of your current checkout, you can skip
this step. From the root of the repository:

```sh
docker build -t matrixdotorg/synapse -f docker/Dockerfile .
```

This will build an image with the tag `matrixdotorg/synapse`.

Next, we build a new image with worker support based on `matrixdotorg/synapse:latest`. 
Again, from the root of the repository:

```sh
docker build -t matrixdotorg/synapse-workers -f docker/Dockerfile-workers .
```

This will build an image with the tag` matrixdotorg/synapse-workers`.

It's worth noting at this point that this image is fully functional, and 
can be used for testing against locally. See instructions for using the container 
under
[Running the Dockerfile-worker image standalone](#running-the-dockerfile-worker-image-standalone)
below.

Finally, build the Synapse image for Complement, which is based on
`matrixdotorg/synapse-workers`. You will need a local checkout of Complement. Change to
the root of your Complement checkout and run:

```sh
docker build -t matrixdotorg/complement-synapse-workers -f dockerfiles/SynapseWorkers.Dockerfile dockerfiles
```

This will build an image with the tag `complement-synapse`, which can be handed to
Complement for testing via the `COMPLEMENT_BASE_IMAGE` environment variable. Refer to
[Complement's documentation](https://github.com/matrix-org/complement/#running) for
how to run the tests, as well as the various available command line flags.

## Running the Dockerfile-worker image standalone

For manual testing of a multi-process Synapse instance in Docker,
[Dockerfile-workers](Dockerfile-workers) is a Dockerfile that will produce an image
bundling all necessary components together for a workerised homeserver instance.

This includes any desired Synapse worker processes, a nginx to route traffic accordingly,
a redis for worker communication and a supervisord instance to start up and monitor all
processes. You will need to provide your own postgres container to connect to, and TLS 
is not handled by the container.

Once you've built the image using the above instructions, you can run it. Be sure 
you've set up a volume according to the [usual Synapse docker instructions](README.md).
Then run something along the lines of:

```
docker run -d --name synapse \
    --mount type=volume,src=synapse-data,dst=/data \
    -p 8008:8008 \
    -e SYNAPSE_SERVER_NAME=my.matrix.host \
    -e SYNAPSE_REPORT_STATS=no \
    -e POSTGRES_HOST=postgres \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=somesecret \
    -e SYNAPSE_WORKER_TYPES=synchrotron,media_repository,user_dir \
    -e SYNAPSE_WORKERS_WRITE_LOGS_TO_DISK=1 \
    matrixdotorg/synapse-workers
```

...substituting `POSTGRES*` variables for those that match a postgres host you have 
available (usually a running postgres docker container).

The `SYNAPSE_WORKER_TYPES` environment variable is a comma-separated list of workers to
use when running the container. All possible worker names are defined by the keys of the
`WORKERS_CONFIG` variable in [this script](configure_workers_and_start.py), which the
Dockerfile makes use of to generate appropriate worker, nginx and supervisord config
files.

Sharding is supported for a subset of workers, in line with the
[worker documentation](../docs/workers.md). To run multiple instances of a given worker
type, simply specify the type multiple times in `SYNAPSE_WORKER_TYPES`
(e.g `SYNAPSE_WORKER_TYPES=event_creator,event_creator...`).

Otherwise, `SYNAPSE_WORKER_TYPES` can either be left empty or unset to spawn no workers
(leaving only the main process). The container is configured to use redis-based worker
mode.

Logs for workers and the main process are logged to stdout and can be viewed with 
standard `docker logs` tooling. Worker logs contain their worker name 
after the timestamp.

Setting `SYNAPSE_WORKERS_WRITE_LOGS_TO_DISK=1` will cause worker logs to be written to
`<data_dir>/logs/<worker_name>.log`. Logs are kept for 1 week and rotate every day at 00:
00, according to the container's clock. Logging for the main process must still be 
configured by modifying the homeserver's log config in your Synapse data volume.
