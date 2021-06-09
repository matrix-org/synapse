#!/usr/bin/env python
# Copyright 2021 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script reads environment variables and generates a shared Synapse worker,
# nginx and supervisord configs depending on the workers requested.
#
# The environment variables it reads are:
#   * SYNAPSE_SERVER_NAME: The desired server_name of the homeserver.
#   * SYNAPSE_REPORT_STATS: Whether to report stats.
#   * SYNAPSE_WORKER_TYPES: A comma separated list of worker names as specified in WORKER_CONFIG
#         below. Leave empty for no workers, or set to '*' for all possible workers.
#
# NOTE: According to Complement's ENTRYPOINT expectations for a homeserver image (as defined
# in the project's README), this script may be run multiple times, and functionality should
# continue to work if so.

import os
import subprocess
import sys

import jinja2
import yaml

MAIN_PROCESS_HTTP_LISTENER_PORT = 8080


WORKERS_CONFIG = {
    "pusher": {
        "app": "synapse.app.pusher",
        "listener_resources": [],
        "endpoint_patterns": [],
        "shared_extra_conf": {"start_pushers": False},
        "worker_extra_conf": "",
    },
    "user_dir": {
        "app": "synapse.app.user_dir",
        "listener_resources": ["client"],
        "endpoint_patterns": [
            "^/_matrix/client/(api/v1|r0|unstable)/user_directory/search$"
        ],
        "shared_extra_conf": {"update_user_directory": False},
        "worker_extra_conf": "",
    },
    "media_repository": {
        "app": "synapse.app.media_repository",
        "listener_resources": ["media"],
        "endpoint_patterns": [
            "^/_matrix/media/",
            "^/_synapse/admin/v1/purge_media_cache$",
            "^/_synapse/admin/v1/room/.*/media.*$",
            "^/_synapse/admin/v1/user/.*/media.*$",
            "^/_synapse/admin/v1/media/.*$",
            "^/_synapse/admin/v1/quarantine_media/.*$",
        ],
        "shared_extra_conf": {"enable_media_repo": False},
        "worker_extra_conf": "enable_media_repo: true",
    },
    "appservice": {
        "app": "synapse.app.appservice",
        "listener_resources": [],
        "endpoint_patterns": [],
        "shared_extra_conf": {"notify_appservices": False},
        "worker_extra_conf": "",
    },
    "federation_sender": {
        "app": "synapse.app.federation_sender",
        "listener_resources": [],
        "endpoint_patterns": [],
        "shared_extra_conf": {"send_federation": False},
        "worker_extra_conf": "",
    },
    "synchrotron": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client"],
        "endpoint_patterns": [
            "^/_matrix/client/(v2_alpha|r0)/sync$",
            "^/_matrix/client/(api/v1|v2_alpha|r0)/events$",
            "^/_matrix/client/(api/v1|r0)/initialSync$",
            "^/_matrix/client/(api/v1|r0)/rooms/[^/]+/initialSync$",
        ],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "federation_reader": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["federation"],
        "endpoint_patterns": [
            "^/_matrix/federation/(v1|v2)/event/",
            "^/_matrix/federation/(v1|v2)/state/",
            "^/_matrix/federation/(v1|v2)/state_ids/",
            "^/_matrix/federation/(v1|v2)/backfill/",
            "^/_matrix/federation/(v1|v2)/get_missing_events/",
            "^/_matrix/federation/(v1|v2)/publicRooms",
            "^/_matrix/federation/(v1|v2)/query/",
            "^/_matrix/federation/(v1|v2)/make_join/",
            "^/_matrix/federation/(v1|v2)/make_leave/",
            "^/_matrix/federation/(v1|v2)/send_join/",
            "^/_matrix/federation/(v1|v2)/send_leave/",
            "^/_matrix/federation/(v1|v2)/invite/",
            "^/_matrix/federation/(v1|v2)/query_auth/",
            "^/_matrix/federation/(v1|v2)/event_auth/",
            "^/_matrix/federation/(v1|v2)/exchange_third_party_invite/",
            "^/_matrix/federation/(v1|v2)/user/devices/",
            "^/_matrix/federation/(v1|v2)/get_groups_publicised$",
            "^/_matrix/key/v2/query",
        ],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "federation_inbound": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["federation"],
        "endpoint_patterns": ["/_matrix/federation/(v1|v2)/send/"],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "event_persister": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["replication"],
        "endpoint_patterns": [],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "background_worker": {
        "app": "synapse.app.generic_worker",
        "listener_resources": [],
        "endpoint_patterns": [],
        # This worker cannot be sharded. Therefore there should only ever be one background
        # worker, and it should be named background_worker1
        "shared_extra_conf": {"run_background_tasks_on": "background_worker1"},
        "worker_extra_conf": "",
    },
    "event_creator": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client"],
        "endpoint_patterns": [
            "^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/redact",
            "^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/send",
            "^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/(join|invite|leave|ban|unban|kick)$",
            "^/_matrix/client/(api/v1|r0|unstable)/join/",
            "^/_matrix/client/(api/v1|r0|unstable)/profile/",
        ],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "frontend_proxy": {
        "app": "synapse.app.frontend_proxy",
        "listener_resources": ["client", "replication"],
        "endpoint_patterns": ["^/_matrix/client/(api/v1|r0|unstable)/keys/upload"],
        "shared_extra_conf": {},
        "worker_extra_conf": (
            "worker_main_http_uri: http://127.0.0.1:%d"
            % (MAIN_PROCESS_HTTP_LISTENER_PORT,),
        ),
    },
}

# Templates for sections that may be inserted multiple times in config files
SUPERVISORD_PROCESS_CONFIG_BLOCK = """
[program:synapse_{name}]
command=/usr/local/bin/python -m {app} \
    --config-path="{config_path}" \
    --config-path=/conf/workers/shared.yaml \
    --config-path=/conf/workers/{name}.yaml
autorestart=unexpected
priority=500
exitcodes=0
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
"""

NGINX_LOCATION_CONFIG_BLOCK = """
    location ~* {endpoint} {{
        proxy_pass {upstream};
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
    }}
"""

NGINX_UPSTREAM_CONFIG_BLOCK = """
upstream {upstream_worker_type} {{
{body}
}}
"""


# Utility functions
def log(txt: str):
    """Log something to the stdout.

    Args:
        txt: The text to log.
    """
    print(txt)


def error(txt: str):
    """Log something and exit with an error code.

    Args:
        txt: The text to log in error.
    """
    log(txt)
    sys.exit(2)


def convert(src: str, dst: str, **template_vars):
    """Generate a file from a template

    Args:
        src: Path to the input file.
        dst: Path to write to.
        template_vars: The arguments to replace placeholder variables in the template with.
    """
    # Read the template file
    with open(src) as infile:
        template = infile.read()

    # Generate a string from the template. We disable autoescape to prevent template
    # variables from being escaped.
    rendered = jinja2.Template(template, autoescape=False).render(**template_vars)

    # Write the generated contents to a file
    #
    # We use append mode in case the files have already been written to by something else
    # (for instance, as part of the instructions in a dockerfile).
    with open(dst, "a") as outfile:
        # In case the existing file doesn't end with a newline
        outfile.write("\n")

        outfile.write(rendered)


def add_sharding_to_shared_config(
    shared_config: dict,
    worker_type: str,
    worker_name: str,
    worker_port: int,
) -> None:
    """Given a dictionary representing a config file shared across all workers,
    append sharded worker information to it for the current worker_type instance.

    Args:
        shared_config: The config dict that all worker instances share (after being converted to YAML)
        worker_type: The type of worker (one of those defined in WORKERS_CONFIG).
        worker_name: The name of the worker instance.
        worker_port: The HTTP replication port that the worker instance is listening on.
    """
    # The instance_map config field marks the workers that write to various replication streams
    instance_map = shared_config.setdefault("instance_map", {})

    # Worker-type specific sharding config
    if worker_type == "pusher":
        shared_config.setdefault("pusher_instances", []).append(worker_name)

    elif worker_type == "federation_sender":
        shared_config.setdefault("federation_sender_instances", []).append(worker_name)

    elif worker_type == "event_persister":
        # Event persisters write to the events stream, so we need to update
        # the list of event stream writers
        shared_config.setdefault("stream_writers", {}).setdefault("events", []).append(
            worker_name
        )

        # Map of stream writer instance names to host/ports combos
        instance_map[worker_name] = {
            "host": "localhost",
            "port": worker_port,
        }

    elif worker_type == "media_repository":
        # The first configured media worker will run the media background jobs
        shared_config.setdefault("media_instance_running_background_jobs", worker_name)


def generate_base_homeserver_config():
    """Starts Synapse and generates a basic homeserver config, which will later be
    modified for worker support.

    Raises: CalledProcessError if calling start.py returned a non-zero exit code.
    """
    # start.py already does this for us, so just call that.
    # note that this script is copied in in the official, monolith dockerfile
    os.environ["SYNAPSE_HTTP_PORT"] = str(MAIN_PROCESS_HTTP_LISTENER_PORT)
    subprocess.check_output(["/usr/local/bin/python", "/start.py", "migrate_config"])


def generate_worker_files(environ, config_path: str, data_dir: str):
    """Read the desired list of workers from environment variables and generate
    shared homeserver, nginx and supervisord configs.

    Args:
        environ: _Environ[str]
        config_path: Where to output the generated Synapse main worker config file.
        data_dir: The location of the synapse data directory. Where log and
            user-facing config files live.
    """
    # Note that yaml cares about indentation, so care should be taken to insert lines
    # into files at the correct indentation below.

    # shared_config is the contents of a Synapse config file that will be shared amongst
    # the main Synapse process as well as all workers.
    # It is intended mainly for disabling functionality when certain workers are spun up,
    # and adding a replication listener.

    # First read the original config file and extract the listeners block. Then we'll add
    # another listener for replication. Later we'll write out the result.
    listeners = [
        {
            "port": 9093,
            "bind_address": "127.0.0.1",
            "type": "http",
            "resources": [{"names": ["replication"]}],
        }
    ]
    with open(config_path) as file_stream:
        original_config = yaml.safe_load(file_stream)
        original_listeners = original_config.get("listeners")
        if original_listeners:
            listeners += original_listeners

    # The shared homeserver config. The contents of which will be inserted into the
    # base shared worker jinja2 template.
    #
    # This config file will be passed to all workers, included Synapse's main process.
    shared_config = {"listeners": listeners}

    # The supervisord config. The contents of which will be inserted into the
    # base supervisord jinja2 template.
    #
    # Supervisord will be in charge of running everything, from redis to nginx to Synapse
    # and all of its worker processes. Load the config template, which defines a few
    # services that are necessary to run.
    supervisord_config = ""

    # Upstreams for load-balancing purposes. This dict takes the form of a worker type to the
    # ports of each worker. For example:
    # {
    #   worker_type: {1234, 1235, ...}}
    # }
    # and will be used to construct 'upstream' nginx directives.
    nginx_upstreams = {}

    # A map of: {"endpoint": "upstream"}, where "upstream" is a str representing what will be
    # placed after the proxy_pass directive. The main benefit to representing this data as a
    # dict over a str is that we can easily deduplicate endpoints across multiple instances
    # of the same worker.
    #
    # An nginx site config that will be amended to depending on the workers that are
    # spun up. To be placed in /etc/nginx/conf.d.
    nginx_locations = {}

    # Read the desired worker configuration from the environment
    worker_types = environ.get("SYNAPSE_WORKER_TYPES")
    if worker_types is None:
        # No workers, just the main process
        worker_types = []
    else:
        # Split type names by comma
        worker_types = worker_types.split(",")

    # Create the worker configuration directory if it doesn't already exist
    os.makedirs("/conf/workers", exist_ok=True)

    # Start worker ports from this arbitrary port
    worker_port = 18009

    # A counter of worker_type -> int. Used for determining the name for a given
    # worker type when generating its config file, as each worker's name is just
    # worker_type + instance #
    worker_type_counter = {}

    # For each worker type specified by the user, create config values
    for worker_type in worker_types:
        worker_type = worker_type.strip()

        worker_config = WORKERS_CONFIG.get(worker_type)
        if worker_config:
            worker_config = worker_config.copy()
        else:
            log(worker_type + " is an unknown worker type! It will be ignored")
            continue

        new_worker_count = worker_type_counter.setdefault(worker_type, 0) + 1
        worker_type_counter[worker_type] = new_worker_count

        # Name workers by their type concatenated with an incrementing number
        # e.g. federation_reader1
        worker_name = worker_type + str(new_worker_count)
        worker_config.update(
            {"name": worker_name, "port": worker_port, "config_path": config_path}
        )

        # Update the shared config with any worker-type specific options
        shared_config.update(worker_config["shared_extra_conf"])

        # Check if more than one instance of this worker type has been specified
        worker_type_total_count = worker_types.count(worker_type)
        if worker_type_total_count > 1:
            # Update the shared config with sharding-related options if necessary
            add_sharding_to_shared_config(
                shared_config, worker_type, worker_name, worker_port
            )

        # Enable the worker in supervisord
        supervisord_config += SUPERVISORD_PROCESS_CONFIG_BLOCK.format_map(worker_config)

        # Add nginx location blocks for this worker's endpoints (if any are defined)
        for pattern in worker_config["endpoint_patterns"]:
            # Determine whether we need to load-balance this worker
            if worker_type_total_count > 1:
                # Create or add to a load-balanced upstream for this worker
                nginx_upstreams.setdefault(worker_type, set()).add(worker_port)

                # Upstreams are named after the worker_type
                upstream = "http://" + worker_type
            else:
                upstream = "http://localhost:%d" % (worker_port,)

            # Note that this endpoint should proxy to this upstream
            nginx_locations[pattern] = upstream

        # Write out the worker's logging config file

        # Check whether we should write worker logs to disk, in addition to the console
        extra_log_template_args = {}
        if environ.get("SYNAPSE_WORKERS_WRITE_LOGS_TO_DISK"):
            extra_log_template_args["LOG_FILE_PATH"] = "{dir}/logs/{name}.log".format(
                dir=data_dir, name=worker_name
            )

        # Render and write the file
        log_config_filepath = "/conf/workers/{name}.log.config".format(name=worker_name)
        convert(
            "/conf/log.config",
            log_config_filepath,
            worker_name=worker_name,
            **extra_log_template_args,
        )

        # Then a worker config file
        convert(
            "/conf/worker.yaml.j2",
            "/conf/workers/{name}.yaml".format(name=worker_name),
            **worker_config,
            worker_log_config_filepath=log_config_filepath,
        )

        worker_port += 1

    # Build the nginx location config blocks
    nginx_location_config = ""
    for endpoint, upstream in nginx_locations.items():
        nginx_location_config += NGINX_LOCATION_CONFIG_BLOCK.format(
            endpoint=endpoint,
            upstream=upstream,
        )

    # Determine the load-balancing upstreams to configure
    nginx_upstream_config = ""
    for upstream_worker_type, upstream_worker_ports in nginx_upstreams.items():
        body = ""
        for port in upstream_worker_ports:
            body += "    server localhost:%d;\n" % (port,)

        # Add to the list of configured upstreams
        nginx_upstream_config += NGINX_UPSTREAM_CONFIG_BLOCK.format(
            upstream_worker_type=upstream_worker_type,
            body=body,
        )

    # Finally, we'll write out the config files.

    # Shared homeserver config
    convert(
        "/conf/shared.yaml.j2",
        "/conf/workers/shared.yaml",
        shared_worker_config=yaml.dump(shared_config),
    )

    # Nginx config
    convert(
        "/conf/nginx.conf.j2",
        "/etc/nginx/conf.d/matrix-synapse.conf",
        worker_locations=nginx_location_config,
        upstream_directives=nginx_upstream_config,
    )

    # Supervisord config
    convert(
        "/conf/supervisord.conf.j2",
        "/etc/supervisor/conf.d/supervisord.conf",
        main_config_path=config_path,
        worker_config=supervisord_config,
    )

    # Ensure the logging directory exists
    log_dir = data_dir + "/logs"
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)


def start_supervisord():
    """Starts up supervisord which then starts and monitors all other necessary processes

    Raises: CalledProcessError if calling start.py return a non-zero exit code.
    """
    subprocess.run(["/usr/bin/supervisord"], stdin=subprocess.PIPE)


def main(args, environ):
    config_dir = environ.get("SYNAPSE_CONFIG_DIR", "/data")
    config_path = environ.get("SYNAPSE_CONFIG_PATH", config_dir + "/homeserver.yaml")
    data_dir = environ.get("SYNAPSE_DATA_DIR", "/data")

    # override SYNAPSE_NO_TLS, we don't support TLS in worker mode,
    # this needs to be handled by a frontend proxy
    environ["SYNAPSE_NO_TLS"] = "yes"

    # Generate the base homeserver config if one does not yet exist
    if not os.path.exists(config_path):
        log("Generating base homeserver config")
        generate_base_homeserver_config()

    # This script may be run multiple times (mostly by Complement, see note at top of file).
    # Don't re-configure workers in this instance.
    mark_filepath = "/conf/workers_have_been_configured"
    if not os.path.exists(mark_filepath):
        # Always regenerate all other config files
        generate_worker_files(environ, config_path, data_dir)

        # Mark workers as being configured
        with open(mark_filepath, "w") as f:
            f.write("")

    # Start supervisord, which will start Synapse, all of the configured worker
    # processes, redis, nginx etc. according to the config we created above.
    start_supervisord()


if __name__ == "__main__":
    main(sys.argv, os.environ)
