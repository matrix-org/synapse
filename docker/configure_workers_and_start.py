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
    listen 80;
    listen [::]:80;

    # For the federation port
    listen 8448 default_server;
    listen [::]:8448 default_server;

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

    for worker_type in worker_types:
        worker_type = worker_type.strip()

        if worker_type == "pusher":
            # Disable push handling from the main process
            homeserver_config += """
start_pushers: false
            """

            # Enable the pusher worker in supervisord
            supervisord_config += """
[program:synapse_pusher]
command=/usr/local/bin/python -m synapse.app.pusher \
    --config-path="%s" \
    --config-path=/conf/workers/shared.yaml \
    --config-path=/conf/workers/pusher.yaml
autorestart=unexpected
exitcodes=0
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
            """ % (config_path,)

            # This worker does not handle any REST endpoints

        elif worker_type == "appservice":
            # Disable appservice traffic sending from the main process
            homeserver_config += """
            notify_appservices: false
            """

            # Enable the pusher worker in supervisord
            supervisord_config += """
[program:synapse_appservice]
command=/usr/local/bin/python -m synapse.app.appservice \
    --config-path="%s" \
    --config-path=/conf/workers/shared.yaml \
    --config-path=/conf/workers/appservice.yaml
autorestart=unexpected
exitcodes=0
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
            """ % (config_path,)

            # This worker does not handle any REST endpoints

        elif worker_type == "user_dir":
            # Disable user directory updates on the main process
            homeserver_config += """
update_user_directory: false
            """

            # Enable the user directory worker in supervisord
            supervisord_config += """
[program:synapse_user_dir]
command=/usr/local/bin/python -m synapse.app.user_dir \
    --config-path="%s" \
    --config-path=/conf/workers/shared.yaml \
    --config-path=/conf/workers/user_dir.yaml
autorestart=unexpected
exitcodes=0
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
            """ % (config_path,)

            # Route user directory requests to this worker
            nginx_config_body += """
    location ~* ^/_matrix/client/(api/v1|r0|unstable)/user_directory/search$ {
        proxy_pass http://localhost:8010;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
            """

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

    # Generate worker log config files from the templates.
    # The templates are mainly there so that we can inject some environment variable
    # values into them.
    log_config_template_dir = "/conf/workers/log_config_templates/"
    log_config_dir = "/conf/workers/"
    for log_config_filename in os.listdir(log_config_template_dir):
        template_path = log_config_template_dir + log_config_filename
        out_path = log_config_dir + log_config_filename

        convert(template_path, out_path, environ)

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
