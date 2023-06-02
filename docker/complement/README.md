# Unified Complement image for Synapse

This is an image for testing Synapse with [the *Complement* integration test suite][complement].
It contains some insecure defaults that are only suitable for testing purposes,
so **please don't use this image for a production server**.

This multi-purpose image is built on top of `Dockerfile-workers` in the parent directory
and can be switched using environment variables between the following configurations:

- Monolithic Synapse with SQLite (default, or `SYNAPSE_COMPLEMENT_DATABASE=sqlite`)
- Monolithic Synapse with Postgres (`SYNAPSE_COMPLEMENT_DATABASE=postgres`)
- Workerised Synapse with Postgres (`SYNAPSE_COMPLEMENT_DATABASE=postgres` and `SYNAPSE_COMPLEMENT_USE_WORKERS=true`)

The image is self-contained; it contains an integrated Postgres, Redis and Nginx.


## How to get Complement to pass the environment variables through

To pass these environment variables, use [Complement's `COMPLEMENT_SHARE_ENV_PREFIX`][complementEnv]
variable to configure an environment prefix to pass through, then prefix the above options
with that prefix.

Example:
```
COMPLEMENT_SHARE_ENV_PREFIX=PASS_ PASS_SYNAPSE_COMPLEMENT_DATABASE=postgres
```

Consult `scripts-dev/complement.sh` in the repository root for a real example.


[complement]: https://github.com/matrix-org/complement
[complementEnv]: https://github.com/matrix-org/complement/pull/382
