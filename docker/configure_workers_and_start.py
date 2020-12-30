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

DEFAULT_LISTENER_RESOURCES = ["client", "federation"]

WORKERS_CONFIG = {
    "pusher": {
        "app": "synapse.app.pusher",
        "listener_resources": DEFAULT_LISTENER_RESOURCES,
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
        "app": "synapse.app.user_dir",
        "listener_resources": ["media"],
        "endpoint_patterns": [
            "^/_matrix/media/.*$|^/_synapse/admin/v1/(purge_media_cache$|(room|user)/.*/media.*$|media/.*$|quarantine_media/.*$)"
        ],
        "shared_extra_conf": "enable_media_repo: false"
    }
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
    subprocess.check_output(["/usr/local/bin/python", "/start.py", "generate"])


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
    # It is intended mainly for disabling functionality when certain workers are spun up.
    homeserver_config = """
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
priority=900
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
    listen 80;
    listen [::]:80;

    server_name localhost;
    """
    nginx_config_body = ""  # to modify below
    nginx_config_template_end = """
    # Send all other traffic to the main process
    location ~* ^(\/_matrix|\/_synapse) {
        proxy_pass http://localhost:8008;
        proxy_set_header X-Forwarded-For $remote_addr;

        # TODO: Can we move this to the default nginx.conf so all locations are
        # affected?
        #
        # Nginx by default only allows file uploads up to 1M in size
        # Increase client_max_body_size to match max_upload_size defined in homeserver.yaml
        client_max_body_size 50M;
    }
}
"""

    # Read desired worker configuration from environment
    if "SYNAPSE_WORKERS" not in environ:
        error("Environment variable 'SYNAPSE_WORKERS' is mandatory.")

    worker_types = environ.get("SYNAPSE_WORKERS")
    worker_types = worker_types.split(",")

    os.mkdir("/conf/workers")

    worker_port = 18009
    for worker_type in worker_types:
        worker_type = worker_type.strip()

        # TODO handle wrong worker type
        worker_config = WORKERS_CONFIG.get(worker_type).copy()

        # this is not hardcoded bc we want to be able to have several workers
        # of each type ultimately (not supported for now)
        worker_name = worker_type
        worker_config.update({"name": worker_name})

        worker_config.update({"port": worker_port})
        worker_config.update({"config_path": config_path})

        homeserver_config += worker_config['shared_extra_conf']

            # Enable the pusher worker in supervisord
        supervisord_config += """
[program:synapse_{name}]
command=/usr/local/bin/python -m {app} \
    --config-path="{config_path}" \
    --config-path=/conf/workers/shared.yaml \
    --config-path=/conf/workers/{name}.yaml
autorestart=unexpected
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

    # Write out the config files

    # Shared homeserver config
    print(homeserver_config)
    with open("/conf/workers/shared.yaml", "w") as f:
        f.write(homeserver_config)

    # Nginx config
    print()
    print(nginx_config_template_header)
    print(nginx_config_body)
    print(nginx_config_template_end)
    with open("/etc/nginx/conf.d/matrix-synapse.conf", "w") as f:
        f.write(nginx_config_template_header)
        f.write(nginx_config_body)
        f.write(nginx_config_template_end)

    # Supervisord config
    print()
    print(supervisord_config)
    with open("/etc/supervisor/conf.d/supervisord.conf", "w") as f:
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
