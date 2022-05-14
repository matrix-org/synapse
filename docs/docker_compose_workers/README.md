# Setting up Synapse with Workers using Docker Compose

This section describes how deploy and manage Synapse and workers via [Docker Compose](https://docs.docker.com/compose/).

Example worker configuration files can be found [here](workers).

## Example Worker Service in Docker Compose

In order to start the Synapse container as a worker, you must specify an `entrypoint` that loads both the `homeserver.yaml` and the configuration for the worker (`generic_worker_1.yaml` in the example below). You must also include the worker type in the environment variable `SYNAPSE_WORKER` or alternatively pass `-m synapse.app.generic_worker` as part of the `entrypoint`.

### Generic Worker Example

```yaml
synapse-generic-worker-1:
  image: matrixdotorg/synapse:latest
  container_name: synapse-generic-worker-1
  restart: unless-stopped
  entrypoint: ["/start.py", "run", "--config-path=/data/homeserver.yaml", "--config-path=/data/workers/synapse-generic-worker-1.yaml"]
  healthcheck:
    test: ["CMD-SHELL", "curl -fSs http://localhost:8081/health || exit 1"]
    start_period: "5s"
    interval: "15s"
    timeout: "5s"
  volumes:
    - ${VOLUME_PATH}/data:/data:rw # Replace VOLUME_PATH with the path to your Synapse volume
  environment:
    SYNAPSE_WORKER: synapse.app.generic_worker
  # Expose port if required so your reverse proxy can send requests to this worker
  # Port configuration will depend on how the http listener is defined in the worker configuration file
  ports:
    - 8081:8081
  depends_on:
    - synapse
```

### Federation Sender Example

```yaml
synapse-federation-sender-1:
  image: matrixdotorg/synapse:latest
  container_name: synapse-federation-sender-1
  restart: unless-stopped
  entrypoint: ["/start.py", "run", "--config-path=/data/homeserver.yaml", "--config-path=/data/federation_sender_worker_1.yaml"]
  healthcheck:
    disable: true
  volumes:
    - ${VOLUME_PATH}/data:/data:rw # Replace VOLUME_PATH with the path to your Synapse volume
  environment:
    SYNAPSE_WORKER: synapse.app.federation_sender
  depends_on:
    - synapse
```

## `homeserver.yaml` Configuration

