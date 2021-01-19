#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
# nginx and supervisord configs depending on the workers requested

import os
import sys
import subprocess
import jinja2
import yaml

DEFAULT_LISTENER_RESOURCES = ["client", "federation"]

WORKERS_CONFIG = {
    "pusher": {
        "app": "synapse.app.pusher",
        "listener_resources": [],
        "endpoint_patterns": [],
        "shared_extra_conf": "start_pushers: false"
    },
    "user_dir": {
        "app": "synapse.app.user_dir",
        "listener_resources": DEFAULT_LISTENER_RESOURCES,
        "endpoint_patterns": [
            "^/_matrix/client/(api/v1|r0|unstable)/user_directory/search$"
        ],
        "shared_extra_conf": "update_user_directory: false"
    },
    "media_repository": {
        "app": "synapse.app.media_repository",
        "listener_resources": ["media"],
        "endpoint_patterns": [
            "^/_synapse/admin/v1/purge_media_cache$",
            "^/_synapse/admin/v1/room/.*/media.*$",
            "^/_synapse/admin/v1/user/.*/media.*$",
            "^/_synapse/admin/v1/media/.*$",
            "^/_synapse/admin/v1/quarantine_media/.*$",
        ],
        "shared_extra_conf": "enable_media_repo: false"
    },
    "appservice": {
        "app": "synapse.app.appservice",
        "listener_resources": [],
        "endpoint_patterns": [],
        "shared_extra_conf": "notify_appservices: false"
    },
    "federation_sender": {
        "app": "synapse.app.federation_sender",
        "listener_resources": [],
        "endpoint_patterns": [],
        "shared_extra_conf": "send_federation: false"
    },
    "synchrotron": {
        "app": "synapse.app.generic_worker",
        "listener_resources": DEFAULT_LISTENER_RESOURCES,
        "endpoint_patterns": [
            "^/_matrix/client/(v2_alpha|r0)/sync$",
            "^/_matrix/client/(api/v1|v2_alpha|r0)/events$",
            "^/_matrix/client/(api/v1|r0)/initialSync$",
            "^/_matrix/client/(api/v1|r0)/rooms/[^/]+/initialSync$",
        ],
        "shared_extra_conf": ""
    },
    "federation_reader": {
        "app": "synapse.app.generic_worker",
        "listener_resources": DEFAULT_LISTENER_RESOURCES,
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
        "shared_extra_conf": ""
    },
    "federation_inbound": {
        "app": "synapse.app.generic_worker",
        "listener_resources": DEFAULT_LISTENER_RESOURCES,
        "endpoint_patterns": [
            "/_matrix/federation/(v1|v2)/send/",
        ],
        "shared_extra_conf": ""
    },
}

# Utility functions
def log(txt):
    print(txt)


def error(txt):
    log(txt)
    sys.exit(2)


def convert(src, dst, environ):
    """Generate a file from a template

    Args:
        src (str): path to input file
        dst (str): path to file to write
        environ (dict): environment dictionary, for replacement mappings.
    """
    with open(src) as infile:
        template = infile.read()
    rendered = jinja2.Template(template, autoescape=True).render(**environ)
    print(rendered)
    with open(dst, "w") as outfile:
        outfile.write(rendered)


def generate_base_homeserver_config():
    """Starts Synapse and generates a basic homeserver config, which will later be
    modified for worker support.

    Raises: CalledProcessError if calling start.py return a non-zero exit code.
    """
    # start.py already does this for us, so just call that.
    # note that this script is copied in in the official, monolith dockerfile
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

    # The contents of a Synapse config file that will be added alongside the generated
    # config when running the main Synapse process.
    # It is intended mainly for disabling functionality when certain workers are spun up,
    # and add the replication listener

    # first read the original config file to take listeners config and add the replication one
    listeners = [{
        "port": 9093,
        "bind_address": "127.0.0.1",
        "type": "http",
        "resources":[{
            "names": ["replication"]
        }]
    }]
    with open(config_path) as file_stream:
        original_config = yaml.safe_load(file_stream)
        original_listeners = original_config.get("listeners")
        if original_listeners:
            listeners += original_listeners

    homeserver_config = yaml.dump({"listeners": listeners})

    homeserver_config += """
redis:
    enabled: true

# TODO: remove before prod
suppress_key_server_warning: true
"""

    # The supervisord config
    supervisord_config = """
[supervisord]
nodaemon=true

[program:nginx]
command=/usr/sbin/nginx -g "daemon off;"
priority=500
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
username=www-data
autorestart=true

[program:synapse_main]
command=/usr/local/bin/python -m synapse.app.homeserver \
    --config-path="%s" \
    --config-path=/conf/workers/shared.yaml
priority=1
# Log startup failures to supervisord's stdout/err
# Regular synapse logs will still go in the configured data directory
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
autorestart=unexpected
exitcodes=0

""" % (config_path,)

    # An nginx site config. Will live in /etc/nginx/conf.d
    nginx_config_template_header = """
server {
    # Listen on Synapse's default HTTP port number
    listen 8080;
    listen [::]:8080;

    server_name localhost;

    # Nginx by default only allows file uploads up to 1M in size
    # Increase client_max_body_size to match max_upload_size defined in homeserver.yaml
    client_max_body_size 100M;
    """
    nginx_config_body = ""  # to modify below
    nginx_config_template_end = """
    # Send all other traffic to the main process
    location ~* ^(\/_matrix|\/_synapse) {
        proxy_pass http://localhost:8008;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
"""

    # Read desired worker configuration from environment
    if "SYNAPSE_WORKERS" not in environ:
        worker_types = []
    else:
        worker_types = environ.get("SYNAPSE_WORKERS")
        worker_types = worker_types.split(",")

    os.mkdir("/conf/workers")

    worker_port = 18009
    for worker_type in worker_types:
        worker_type = worker_type.strip()

        worker_config = WORKERS_CONFIG.get(worker_type)
        if worker_config:
            worker_config = worker_config.copy()
        else:
            log(worker_type + " is a wrong worker type ! It will be ignored")
            continue

        # this is not hardcoded bc we want to be able to have several workers
        # of each type ultimately (not supported for now)
        worker_name = worker_type
        worker_config.update({"name": worker_name})

        worker_config.update({"port": worker_port})
        worker_config.update({"config_path": config_path})

        homeserver_config += worker_config['shared_extra_conf'] + "\n"

            # Enable the pusher worker in supervisord
        supervisord_config += """
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
stderr_logfile_maxbytes=0""".format_map(worker_config)


        for pattern in worker_config['endpoint_patterns']:
            nginx_config_body += """
    location ~* %s {
        proxy_pass http://localhost:%s;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
""" % (pattern, worker_port)

        convert("/conf/worker.yaml.j2", "/conf/workers/{name}.yaml".format(name=worker_name), worker_config)

        worker_port += 1

    # Write out the config files. We use append mode for each in case the
    # files may have already been written to by others.

    # Shared homeserver config
    print(homeserver_config)
    with open("/conf/workers/shared.yaml", "a") as f:
        f.write(homeserver_config)

    # Nginx config
    print()
    print(nginx_config_template_header)
    print(nginx_config_body)
    print(nginx_config_template_end)
    with open("/etc/nginx/conf.d/matrix-synapse.conf", "a") as f:
        f.write(nginx_config_template_header)
        f.write(nginx_config_body)
        f.write(nginx_config_template_end)

    # Supervisord config
    print()
    print(supervisord_config)
    with open("/etc/supervisor/conf.d/supervisord.conf", "a") as f:
        f.write(supervisord_config)

    # Ensure the logging directory exists
    log_dir = data_dir + "/logs"
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)


def start_supervisord():
    """Starts up supervisord which then starts and monitors all other necessary processes

    Raises: CalledProcessError if calling start.py return a non-zero exit code.
    """
    subprocess.check_output(["/usr/bin/supervisord"])


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

    # Always regenerate all other config files
    generate_worker_files(environ, config_path, data_dir)

    # Start supervisord, which will start Synapse, all of the configured worker
    # processes, redis, nginx etc. according to the config we created above.
    start_supervisord()


if __name__ == "__main__":
    main(sys.argv, os.environ)
