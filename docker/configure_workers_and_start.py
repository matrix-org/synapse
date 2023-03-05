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
#   * SYNAPSE_WORKER_TYPES: A comma separated list of worker names as specified in WORKERS_CONFIG
#         below. Leave empty for no workers. Add a ':' and a number at the end to
#         multiply that worker. Append multiple worker types with '+' to merge the
#         worker types into a single worker. Add a name and a '=' to the front of a
#         worker type to give this instance a name in logs and nginx.
#         Examples:
#         SYNAPSE_WORKER_TYPES='event_persister, federation_sender, client_reader'
#         SYNAPSE_WORKER_TYPES='event_persister:2, federation_sender:2, client_reader'
#         SYNAPSE_WORKER_TYPES='stream_writers=account_data+presence+typing'
#   * SYNAPSE_AS_REGISTRATION_DIR: If specified, a directory in which .yaml and .yml files
#         will be treated as Application Service registration files.
#   * SYNAPSE_TLS_CERT: Path to a TLS certificate in PEM format.
#   * SYNAPSE_TLS_KEY: Path to a TLS key. If this and SYNAPSE_TLS_CERT are specified,
#         Nginx will be configured to serve TLS on port 8448.
#   * SYNAPSE_USE_EXPERIMENTAL_FORKING_LAUNCHER: Whether to use the forking launcher,
#         only intended for usage in Complement at the moment.
#         No stability guarantees are provided.
#   * SYNAPSE_LOG_LEVEL: Set this to DEBUG, INFO, WARNING or ERROR to change the
#         log level. INFO is the default.
#   * SYNAPSE_LOG_SENSITIVE: If unset, SQL and SQL values won't be logged,
#         regardless of the SYNAPSE_LOG_LEVEL setting.
#
# NOTE: According to Complement's ENTRYPOINT expectations for a homeserver image (as defined
# in the project's README), this script may be run multiple times, and functionality should
# continue to work if so.

import os
import platform
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import (
    Any,
    Dict,
    List,
    Mapping,
    MutableMapping,
    NoReturn,
    Optional,
    Set,
    SupportsIndex,
)

import yaml
from jinja2 import Environment, FileSystemLoader

MAIN_PROCESS_HTTP_LISTENER_PORT = 8080

# A simple name used as a placeholder in the WORKERS_CONFIG below. This will be replaced
# during processing with the name of the worker.
WORKER_PLACEHOLDER_NAME = "placeholder_name"

# Workers with exposed endpoints needs either "client", "federation", or "media" listener_resources
# Watching /_matrix/client needs a "client" listener
# Watching /_matrix/federation needs a "federation" listener
# Watching /_matrix/media and related needs a "media" listener
# Stream Writers require "client" and "replication" listeners because they
#   have to attach by instance_map to the master process and have client endpoints.
WORKERS_CONFIG: Dict[str, Dict[str, Any]] = {
    "pusher": {
        "app": "synapse.app.generic_worker",
        "listener_resources": [],
        "endpoint_patterns": [],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "user_dir": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client"],
        "endpoint_patterns": [
            "^/_matrix/client/(api/v1|r0|v3|unstable)/user_directory/search$"
        ],
        "shared_extra_conf": {
            "update_user_directory_from_worker": WORKER_PLACEHOLDER_NAME
        },
        "worker_extra_conf": "",
    },
    "media_repository": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["media"],
        "endpoint_patterns": [
            "^/_matrix/media/",
            "^/_synapse/admin/v1/purge_media_cache$",
            "^/_synapse/admin/v1/room/.*/media.*$",
            "^/_synapse/admin/v1/user/.*/media.*$",
            "^/_synapse/admin/v1/media/.*$",
            "^/_synapse/admin/v1/quarantine_media/.*$",
        ],
        # The first configured media worker will run the media background jobs
        "shared_extra_conf": {
            "enable_media_repo": False,
            "media_instance_running_background_jobs": WORKER_PLACEHOLDER_NAME,
        },
        "worker_extra_conf": "enable_media_repo: true",
    },
    "appservice": {
        "app": "synapse.app.generic_worker",
        "listener_resources": [],
        "endpoint_patterns": [],
        "shared_extra_conf": {
            "notify_appservices_from_worker": WORKER_PLACEHOLDER_NAME
        },
        "worker_extra_conf": "",
    },
    "federation_sender": {
        "app": "synapse.app.generic_worker",
        "listener_resources": [],
        "endpoint_patterns": [],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "synchrotron": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client"],
        "endpoint_patterns": [
            "^/_matrix/client/(v2_alpha|r0|v3)/sync$",
            "^/_matrix/client/(api/v1|v2_alpha|r0|v3)/events$",
            "^/_matrix/client/(api/v1|r0|v3)/initialSync$",
            "^/_matrix/client/(api/v1|r0|v3)/rooms/[^/]+/initialSync$",
        ],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "client_reader": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client"],
        "endpoint_patterns": [
            "^/_matrix/client/(api/v1|r0|v3|unstable)/publicRooms$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/joined_members$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/context/.*$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/members$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/state$",
            "^/_matrix/client/v1/rooms/.*/hierarchy$",
            "^/_matrix/client/(v1|unstable)/rooms/.*/relations/",
            "^/_matrix/client/v1/rooms/.*/threads$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/login$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/account/3pid$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/account/whoami$",
            "^/_matrix/client/versions$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/voip/turnServer$",
            "^/_matrix/client/(r0|v3|unstable)/register$",
            "^/_matrix/client/(r0|v3|unstable)/auth/.*/fallback/web$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/messages$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/event",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/joined_rooms",
            "^/_matrix/client/(api/v1|r0|v3|unstable/.*)/rooms/.*/aliases",
            "^/_matrix/client/v1/rooms/.*/timestamp_to_event$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/search",
            "^/_matrix/client/(r0|v3|unstable)/user/.*/filter(/|$)",
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
            "^/_matrix/federation/v1/timestamp_to_event/",
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
        # This worker cannot be sharded. Therefore, there should only ever be one
        # background worker. This is enforced for the safety of your database.
        "shared_extra_conf": {"run_background_tasks_on": WORKER_PLACEHOLDER_NAME},
        "worker_extra_conf": "",
    },
    "event_creator": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client"],
        "endpoint_patterns": [
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/redact",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/send",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/(join|invite|leave|ban|unban|kick)$",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/join/",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/knock/",
            "^/_matrix/client/(api/v1|r0|v3|unstable)/profile/",
            "^/_matrix/client/(v1|unstable/org.matrix.msc2716)/rooms/.*/batch_send",
        ],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "frontend_proxy": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client", "replication"],
        "endpoint_patterns": ["^/_matrix/client/(api/v1|r0|v3|unstable)/keys/upload"],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "account_data": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client", "replication"],
        "endpoint_patterns": [
            "^/_matrix/client/(r0|v3|unstable)/.*/tags",
            "^/_matrix/client/(r0|v3|unstable)/.*/account_data",
        ],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "presence": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client", "replication"],
        "endpoint_patterns": ["^/_matrix/client/(api/v1|r0|v3|unstable)/presence/"],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "receipts": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client", "replication"],
        "endpoint_patterns": [
            "^/_matrix/client/(r0|v3|unstable)/rooms/.*/receipt",
            "^/_matrix/client/(r0|v3|unstable)/rooms/.*/read_markers",
        ],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "to_device": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client", "replication"],
        "endpoint_patterns": ["^/_matrix/client/(r0|v3|unstable)/sendToDevice/"],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
    "typing": {
        "app": "synapse.app.generic_worker",
        "listener_resources": ["client", "replication"],
        "endpoint_patterns": [
            "^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/typing"
        ],
        "shared_extra_conf": {},
        "worker_extra_conf": "",
    },
}

# Templates for sections that may be inserted multiple times in config files
NGINX_LOCATION_CONFIG_BLOCK = """
    location ~* {endpoint} {{
        proxy_pass {upstream};
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
    }}
"""

NGINX_UPSTREAM_CONFIG_BLOCK = """
upstream {upstream_worker_base_name} {{
{body}
}}
"""


# Utility functions
def log(txt: str) -> None:
    print(txt)


def error(txt: str) -> NoReturn:
    print(txt, file=sys.stderr)
    sys.exit(2)


def flush_buffers() -> None:
    sys.stdout.flush()
    sys.stderr.flush()


def convert(src: str, dst: str, **template_vars: object) -> None:
    """Generate a file from a template

    Args:
        src: Path to the input file.
        dst: Path to write to.
        template_vars: The arguments to replace placeholder variables in the template with.
    """
    # Read the template file
    # We disable autoescape to prevent template variables from being escaped,
    # as we're not using HTML.
    env = Environment(loader=FileSystemLoader(os.path.dirname(src)), autoescape=False)
    template = env.get_template(os.path.basename(src))

    # Generate a string from the template.
    rendered = template.render(**template_vars)

    # Write the generated contents to a file
    #
    # We use append mode in case the files have already been written to by something else
    # (for instance, as part of the instructions in a dockerfile).
    with open(dst, "a") as outfile:
        # In case the existing file doesn't end with a newline
        outfile.write("\n")

        outfile.write(rendered)


def add_worker_roles_to_shared_config(
    shared_config: dict,
    worker_type_set: Set[str],
    worker_name: str,
    worker_port: int,
) -> None:
    """Given a dictionary representing a config file shared across all workers,
    append appropriate worker information to it for the current worker_type instance.

    Args:
        shared_config: The config dict that all worker instances share (after being
            converted to YAML)
        worker_type_set: The type of worker (one of those defined in WORKERS_CONFIG).
            This list can be a single worker type or multiple.
        worker_name: The name of the worker instance.
        worker_port: The HTTP replication port that the worker instance is listening on.
    """
    # The instance_map config field marks the workers that write to various replication
    # streams
    instance_map = shared_config.setdefault("instance_map", {})

    # This is a list of the stream_writers that there can be only one of. Events can be
    # sharded, and therefore doesn't belong here.
    singular_stream_writers = [
        "account_data",
        "presence",
        "receipts",
        "to_device",
        "typing",
    ]

    # Worker-type specific sharding config. Now a single worker can fulfill multiple
    # roles, check each.
    if "pusher" in worker_type_set:
        shared_config.setdefault("pusher_instances", []).append(worker_name)

    if "federation_sender" in worker_type_set:
        shared_config.setdefault("federation_sender_instances", []).append(worker_name)

    if "event_persister" in worker_type_set:
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

    # Update the list of stream writers. It's convenient that the name of the worker
    # type is the same as the stream to write. Iterate over the whole list in case there
    # is more than one.
    for worker in worker_type_set:
        if worker in singular_stream_writers:
            shared_config.setdefault("stream_writers", {}).setdefault(
                worker, []
            ).append(worker_name)

            # Map of stream writer instance names to host/ports combos
            # For now, all stream writers need http replication ports
            instance_map[worker_name] = {
                "host": "localhost",
                "port": worker_port,
            }


def merge_worker_template_configs(
    existing_dict: Dict[str, Any] | None,
    to_be_merged_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """When given an existing dict of worker template configuration consisting with both
        dicts and lists, merge new template data from WORKERS_CONFIG(or create) and
        return new dict.

    Args:
        existing_dict: Either an existing worker template or a fresh blank one.
        to_be_merged_dict: The template from WORKERS_CONFIGS to be merged into
            existing_dict.
    Returns: The newly merged together dict values.
    """
    new_dict: Dict[str, Any] = {}
    if not existing_dict:
        # It doesn't exist yet, just use the new dict(but take a copy not a reference)
        new_dict = to_be_merged_dict.copy()
    else:
        for i in to_be_merged_dict.keys():
            if (i == "endpoint_patterns") or (i == "listener_resources"):
                # merge the two lists, remove duplicates
                new_dict[i] = list(set(existing_dict[i] + to_be_merged_dict[i]))
            elif i == "shared_extra_conf":
                # merge dictionary's, the worker name will be replaced later
                new_dict[i] = {**existing_dict[i], **to_be_merged_dict[i]}
            elif i == "worker_extra_conf":
                # There is only one worker type that has a 'worker_extra_conf' and it is
                # the media_repo. Since duplicate worker types on the same worker don't
                # work, this is fine.
                new_dict[i] = existing_dict[i] + to_be_merged_dict[i]
            else:
                # Everything else should be identical, like "app", which only works
                # because all apps are now generic_workers.
                new_dict[i] = to_be_merged_dict[i]
    return new_dict


def insert_worker_name_for_worker_config(
    existing_dict: Dict[str, Any], worker_name: str
) -> Dict[str, Any]:
    """Insert a given worker name into the worker's configuration dict.

    Args:
        existing_dict: The worker_config dict that is imported into shared_config.
        worker_name: The name of the worker to insert.
    Returns: Copy of the dict with newly inserted worker name
    """
    dict_to_edit = existing_dict.copy()
    for k, v in dict_to_edit["shared_extra_conf"].items():
        # Only proceed if it's the placeholder name string
        if v == WORKER_PLACEHOLDER_NAME:
            dict_to_edit["shared_extra_conf"][k] = worker_name
    return dict_to_edit


def apply_requested_multiplier_for_worker(worker_types: List[str]) -> List[str]:
    """
    Apply multiplier(if found) by returning a new expanded list with some basic error
    checking.

    Args:
        worker_types: The unprocessed List of requested workers
    Returns:
        A new list with all requested workers expanded.
    """
    # Checking performed:
    # 1. if worker:2 or more is declared, it will create additional workers up to number
    # 2. if worker:1, it will create a single copy of this worker as if no number was
    #   given
    # 3. if worker:0 is declared, this worker will be ignored. This is to allow for
    #   scripting and automated expansion and is intended behaviour.
    # 4. if worker:NaN or is a negative number, it will error and log it.
    new_worker_types = []
    for worker_type in worker_types:
        if ":" in worker_type:
            worker_type_components = split_and_strip_string(worker_type, ":", 1)
            worker_count = 0
            # Should only be 2 components, a type of worker(s) and an integer as a
            # string. Cast the number as an int then it can be used as a counter.
            try:
                worker_count = int(worker_type_components[1])
            except ValueError:
                error(
                    f"Bad number in worker count for '{worker_type}': "
                    f"'{worker_type_components[1]}' is not an integer"
                )

            # As long as there are more than 0, we add one to the list to make below.
            for _ in range(worker_count):
                new_worker_types.append(worker_type_components[0])

        else:
            # If it's not a real worker_type, it will error out later.
            new_worker_types.append(worker_type)
    return new_worker_types


def is_sharding_allowed_for_worker_type(worker_type: str) -> bool:
    """Helper to check to make sure worker types that cannot have multiples do not.

    Args:
        worker_type: The type of worker to check against.
    Returns: True if allowed, False if not
    """
    return worker_type not in [
        "background_worker",
        "account_data",
        "presence",
        "receipts",
        "typing",
        "to_device",
    ]


def split_and_strip_string(
    given_string: str, split_char: str, max_split: SupportsIndex = -1
) -> List:
    # Removes whitespace from ends of result strings before adding to list. Allow for
    # overriding 'maxsplit' kwarg, default being -1 to signify no maximum.
    return [x.strip() for x in given_string.split(split_char, maxsplit=max_split)]


def generate_base_homeserver_config() -> None:
    """Starts Synapse and generates a basic homeserver config, which will later be
    modified for worker support.

    Raises: CalledProcessError if calling start.py returned a non-zero exit code.
    """
    # start.py already does this for us, so just call that.
    # note that this script is copied in in the official, monolith dockerfile
    os.environ["SYNAPSE_HTTP_PORT"] = str(MAIN_PROCESS_HTTP_LISTENER_PORT)
    subprocess.run(["/usr/local/bin/python", "/start.py", "migrate_config"], check=True)


def parse_worker_types_from_env(
    requested_worker_types: List[str],
) -> Dict[str, Dict[str, Any]]:
    """Read the desired list of worker from environment variables and prepare the data
    for use in generating worker config files while also checking for potential gotchas.

    Args:
        requested_worker_types: The string pulled from the environment containing
            the worker requested data.

    Returns: A  dict of all information needed to generate worker files. Format:
        {'worker_name':
            {'worker_base_name': 'base_name'},

            {'worker_roles_set':
                Set{'worker_type', 'other_worker_type'}
            }
        }
    """
    # Checking performed:
    #   1. If a requested name contains a space
    #   2. If a requested name contains either kind of quote mark
    #   3. If a requested name ends with a digit

    # A counter of worker_type -> int. Used for determining the name for a given
    # worker type(s) when generating its config file, as each worker's name is just
    # worker_(name|type(s)) + instance #
    worker_type_counter: Dict[str, int] = defaultdict(int)

    # Similar to above, but more finely grained. This is used to determine we don't have
    # more than a single worker for cases where multiples would be bad(e.g. presence).
    worker_type_shard_counter: Dict[str, int] = defaultdict(int)

    # Dict of worker name's. This is used to check that a name requested doesn't clash
    # with an existing name in the context of a differing worker_type, as it will error
    # with 'Address in use'(e.g. "to_device, to_device=typing" would not work).
    # Follows the pattern:
    # ["worker_name": "worker_type(s)"]
    worker_name_checklist: Dict[str, str] = {}

    # The final result of all this processing
    dict_to_return: Dict[str, Any] = {}

    # Handle any multipliers requested for a given worker.
    multiple_processed_worker_types = apply_requested_multiplier_for_worker(
        requested_worker_types
    )

    # Check each requested worker for a requested name
    for worker_type_string in multiple_processed_worker_types:
        # Shortcut these to avoid processing and skip an 'else' block when no worker
        # name is actually requested.
        requested_worker_name = ""
        new_worker_type_string = worker_type_string
        # First, check if a name is requested
        if "=" in worker_type_string:
            # Split on "=", remove extra whitespace from ends then make list
            worker_type_split = split_and_strip_string(worker_type_string, "=")
            if len(worker_type_split) > 2:
                error(
                    "To many worker names requested for a single worker, or to many "
                    f"'='. Please fix: {worker_type_string}"
                )
            # if there was no name given, this will still be an empty string
            requested_worker_name = worker_type_split[0]

            # Check the last character of a requested name is not a number. This can
            # cause an error that comes across during startup as an exception in
            # 'startListening' and ends with 'Address already in use' for the port.
            # This only seems to occur when requesting more than 10 of a given
            # worker_type, otherwise it would be ok.
            if requested_worker_name[-1].isdigit():
                error(
                    "Found a number at the end of the requested worker name: "
                    f"{requested_worker_name}. This is not allowed as it will cause "
                    "exceptions with 'Address already in use'. Recommend appending an "
                    "underscore after the number if this what you really want to do."
                )

            # Reassign the worker_type string with no name on it.
            new_worker_type_string = worker_type_split[1]

        # At this point, we have:
        #   requested_worker_name which might be an empty string
        #   new_worker_type_string which might still be what it was when it came in

        # Split the worker_type_string on "+", remove whitespace from ends then make
        # the list a set so it's deduplicated. Hopefully no one tries to put 2
        # pushers on the same worker(as it would consolidate into one).
        workers_roles_list = split_and_strip_string(new_worker_type_string, "+")
        workers_roles_set: Set[str] = set(workers_roles_list)

        # Shortcut this here, then it only has to survive intact(most of the time it
        # will just pass right through)
        worker_base_name = new_worker_type_string
        if requested_worker_name:
            worker_base_name = requested_worker_name
            # It'll be useful to have this in the log in case it's a complex of many
            # workers merged together. Note for Complement: it would only be seen in the
            # logs for blueprint construction(which are not collected).
            log(
                f"Worker name request found: '{requested_worker_name}'"
                f", for: {workers_roles_set}"
            )

        else:
            # The worker name will be the worker_type, however if spaces exist
            # between concatenated worker_types and the "+" because of readability,
            # it will error on startup. Recombine worker_types without spaces and log.
            # Allows for human readability while declaring a complex worker type, e.g.
            # 'event_persister + federation_reader + federation_sender + pusher'
            if (len(workers_roles_set) > 1) and (" " in worker_base_name):
                worker_base_name = "+".join(sorted(workers_roles_set))
                log(
                    "Default worker name would have contained spaces, which is not "
                    f"allowed: '{worker_type_string}'. Reformed name to not contain "
                    f"spaces: '{worker_base_name}'"
                )

        # At this point, we have:
        #   worker_base_name which might be identical to
        #   new_worker_type_string which might still be what it was when it came in
        #   worker_roles_set which is a Set of what worker_types are requested

        # Uncommon mistake that will cause problems. Name string containing quotes
        # or spaces will do Bad Things to filenames and probably nginx too.
        if (
            (" " in worker_base_name)
            or ('"' in worker_base_name)
            or ("'" in worker_base_name)
        ):
            error(
                "Requesting a worker name containing a quote mark or a space is "
                "not allowed, as it would raise a FileNotFoundError. Please fix: "
                f"{worker_base_name}"
            )

        # This counter is used for naming workers with an incrementing number. Use the
        # worker_base_name for the index
        worker_type_counter[worker_base_name] += 1

        # Name workers by their type or requested name concatenated with an
        # incrementing number. e.g. federation_reader1 or event_creator+event_persister1
        worker_name = worker_base_name + str(worker_type_counter[worker_base_name])

        # Now that the worker name is settled, check this name isn't used for a
        # different worker_type. If it's not allowed, will error and stop. If no
        # issues, it will be added to the counter. This will prevent accidentally
        # naming a worker by a worker_type. e.g. 'pusher, pusher=user_dir'
        # Make sure the worker types being checked are deterministic.
        deterministic_worker_role_string = "+".join(sorted(workers_roles_set))
        check_worker_type = worker_name_checklist.get(worker_base_name)
        # Either this doesn't exist yet, or it matches with a twin
        if (check_worker_type is None) or (
            check_worker_type == deterministic_worker_role_string
        ):
            # This is a no-op if it exists, which is expected to avoid the else block
            worker_name_checklist.setdefault(
                worker_base_name, deterministic_worker_role_string
            )

        else:
            error(
                f"Can not use {worker_name} for {deterministic_worker_role_string}. It "
                f"is already in use by {check_worker_type}"
            )

        # Make sure we don't allow sharding for a worker type that doesn't support it.
        # Will error and stop if it is a problem, e.g. 'background_worker'.
        for worker_role in workers_roles_set:
            if worker_role in worker_type_shard_counter:
                if not is_sharding_allowed_for_worker_type(worker_role):
                    error(
                        f"There can be only a single worker with {worker_role} "
                        "type. Please recount and remove."
                    )
            # Not in shard counter, must not have seen it yet, add it.
            worker_type_shard_counter[worker_role] += 1

        # The worker has survived the gauntlet of why it can't exist. Add it to the pile
        dict_to_return.setdefault(worker_name, {}).setdefault(
            "worker_base_name", worker_base_name
        )
        dict_to_return.setdefault(worker_name, {}).setdefault(
            "worker_roles_set", set()
        ).update(workers_roles_set)

    return dict_to_return


def generate_worker_files(
    environ: Mapping[str, str],
    config_path: str,
    data_dir: str,
    requested_worker_types: Dict[str, Any],
) -> None:
    """Read the desired workers(if any) that is passed in and generate shared
        homeserver, nginx and supervisord configs.

    Args:
        environ: os.environ instance.
        config_path: The location of the generated Synapse main worker config file.
        data_dir: The location of the synapse data directory. Where log and
            user-facing config files live.
        requested_worker_types: A Dict containing requested workers in the format of
            {'worker_name1': {'worker_type', ...}}
    """
    # Note that yaml cares about indentation, so care should be taken to insert lines
    # into files at the correct indentation below.

    # First read the original config file and extract the listeners block. Then we'll
    # add another listener for replication. Later we'll write out the result to the
    # shared config file.
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
    # base shared worker jinja2 template. This config file will be passed to all
    # workers, included Synapse's main process. It is intended mainly for disabling
    # functionality when certain workers are spun up, and adding a replication listener.
    shared_config: Dict[str, Any] = {"listeners": listeners}

    # List of dicts that describe workers.
    # We pass this to the Supervisor template later to generate the appropriate
    # program blocks.
    worker_descriptors: List[Dict[str, Any]] = []

    # Upstreams for load-balancing purposes. This dict takes the form of the base worker
    # name to the ports of each worker. For example:
    # {
    #   worker_base_name: {1234, 1235, ...}}
    # }
    # and will be used to construct 'upstream' nginx directives.
    nginx_upstreams: Dict[str, Set[int]] = {}

    # A temporary location dict that will help assemble port data for load-balancing
    nginx_preprocessed_locations: Dict[str, Set[int]] = {}

    # A map of: {"endpoint": "upstream"}, where "upstream" is a str representing what
    # will be placed after the proxy_pass directive. The main benefit to representing
    # this data as a dict over a str is that we can easily deduplicate endpoints
    # across multiple instances of the same worker. The final rendering will be combined
    # with nginx_upstreams and placed in /etc/nginx/conf.d.
    nginx_locations: Dict[str, str] = {}

    # Create the worker configuration directory if it doesn't already exist
    os.makedirs("/conf/workers", exist_ok=True)

    # Start worker ports from this arbitrary port
    worker_port = 18009

    # A list of internal endpoints to healthcheck, starting with the main process
    # which exists even if no workers do.
    healthcheck_urls = ["http://localhost:8080/health"]

    # For each worker type specified by the user, create config values and write it's
    # yaml config file
    for worker_name, worker_type_data in requested_worker_types.items():
        worker_type_set = worker_type_data.get("worker_roles_set")

        # The collected and processed data will live here.
        worker_config: Dict[str, Any] = {}

        # Merge all worker config templates for this worker into a single config
        for worker_type in worker_type_set:
            # Verify this is a real defined worker type. If it's not, stop everything so
            # it can be fixed.
            copy_of_template_config = WORKERS_CONFIG.get(worker_type)
            if copy_of_template_config:
                # So it's not a reference pointer
                copy_of_template_config = copy_of_template_config.copy()
            else:
                error(
                    f"{worker_type} is an unknown worker type! Was found in "
                    f"{worker_type_set}. Please fix!"
                )

            # Merge worker type template configuration data. It's a combination of lists
            # and dicts, so use this helper.
            worker_config = merge_worker_template_configs(
                worker_config, copy_of_template_config
            )

        # Replace placeholder names in the config template with the actual worker name.
        worker_config = insert_worker_name_for_worker_config(worker_config, worker_name)

        worker_config.update(
            {"name": worker_name, "port": str(worker_port), "config_path": config_path}
        )

        # Update the shared config with any worker-type specific options. Do a dance so
        # the first of a given worker type gets to stay assigned.
        worker_config["shared_extra_conf"].update(shared_config)
        shared_config.update(worker_config["shared_extra_conf"])

        healthcheck_urls.append("http://localhost:%d/health" % (worker_port,))

        # Update the shared config with sharding-related options if necessary
        add_worker_roles_to_shared_config(
            shared_config, worker_type_set, worker_name, worker_port
        )

        # Enable the worker in supervisord
        worker_descriptors.append(worker_config)

        # Add nginx location blocks for this worker's endpoints (if any are defined)
        for pattern in worker_config["endpoint_patterns"]:
            # Need more data to determine whether we need to load-balance this worker.
            # Collect all the port numbers for a given endpoint
            nginx_preprocessed_locations.setdefault(pattern, set()).add(worker_port)

        # Write out the worker's logging config file
        log_config_filepath = generate_worker_log_config(environ, worker_name, data_dir)

        # Then a worker config file
        convert(
            "/conf/worker.yaml.j2",
            "/conf/workers/{name}.yaml".format(name=worker_name),
            **worker_config,
            worker_log_config_filepath=log_config_filepath,
        )

        worker_port += 1

    # Re process all nginx upstream data. Worker_descriptors contains all the port data,
    # cross-reference that with the worker_base_name in requested_worker_types.
    for pattern, port_set in nginx_preprocessed_locations.items():
        if len(port_set) > 1:
            # Only process upstreams for multiple port arrangements
            upstream_name: Set[str] = set()
            for worker in worker_descriptors:
                # Find the port we want
                if int(worker["port"]) in port_set:
                    # Capture the name. We want the base name as they will be grouped
                    # together.
                    upstream_name.add(
                        requested_worker_types[worker["name"]].get("worker_base_name")
                    )

            # Join it all up nice and pretty with a double underscore
            upstream = "__".join(sorted(upstream_name))
            upstream_location = "http://" + upstream
            # And save the port numbers for writing out below
            nginx_upstreams[upstream] = port_set

        else:
            # Only a single port, just use that
            (unpacked_port,) = port_set
            upstream_location = "http://localhost:%d" % unpacked_port

        nginx_locations[pattern] = upstream_location

    # Build the nginx location config blocks
    nginx_location_config = ""
    for endpoint, upstream in nginx_locations.items():
        nginx_location_config += NGINX_LOCATION_CONFIG_BLOCK.format(
            endpoint=endpoint,
            upstream=upstream,
        )

    # Determine the load-balancing upstreams to configure
    nginx_upstream_config = ""

    for upstream_worker_base_name, upstream_worker_ports in nginx_upstreams.items():
        body = ""
        for port in upstream_worker_ports:
            body += "    server localhost:%d;\n" % (port,)

        # Add to the list of configured upstreams
        nginx_upstream_config += NGINX_UPSTREAM_CONFIG_BLOCK.format(
            upstream_worker_base_name=upstream_worker_base_name,
            body=body,
        )

    # Finally, we'll write out the config files.

    # log config for the master process
    master_log_config = generate_worker_log_config(environ, "master", data_dir)
    shared_config["log_config"] = master_log_config

    # Find application service registrations
    appservice_registrations = None
    appservice_registration_dir = os.environ.get("SYNAPSE_AS_REGISTRATION_DIR")
    if appservice_registration_dir:
        # Scan for all YAML files that should be application service registrations.
        appservice_registrations = [
            str(reg_path.resolve())
            for reg_path in Path(appservice_registration_dir).iterdir()
            if reg_path.suffix.lower() in (".yaml", ".yml")
        ]

    workers_in_use = len(requested_worker_types) > 0

    # Shared homeserver config
    convert(
        "/conf/shared.yaml.j2",
        "/conf/workers/shared.yaml",
        shared_worker_config=yaml.dump(shared_config),
        appservice_registrations=appservice_registrations,
        enable_redis=workers_in_use,
        workers_in_use=workers_in_use,
    )

    # Nginx config
    convert(
        "/conf/nginx.conf.j2",
        "/etc/nginx/conf.d/matrix-synapse.conf",
        worker_locations=nginx_location_config,
        upstream_directives=nginx_upstream_config,
        tls_cert_path=os.environ.get("SYNAPSE_TLS_CERT"),
        tls_key_path=os.environ.get("SYNAPSE_TLS_KEY"),
    )

    # Supervisord config
    os.makedirs("/etc/supervisor", exist_ok=True)
    convert(
        "/conf/supervisord.conf.j2",
        "/etc/supervisor/supervisord.conf",
        main_config_path=config_path,
        enable_redis=workers_in_use,
    )

    convert(
        "/conf/synapse.supervisord.conf.j2",
        "/etc/supervisor/conf.d/synapse.conf",
        workers=worker_descriptors,
        main_config_path=config_path,
        use_forking_launcher=environ.get("SYNAPSE_USE_EXPERIMENTAL_FORKING_LAUNCHER"),
    )

    # healthcheck config
    convert(
        "/conf/healthcheck.sh.j2",
        "/healthcheck.sh",
        healthcheck_urls=healthcheck_urls,
    )

    # Ensure the logging directory exists
    log_dir = data_dir + "/logs"
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)


def generate_worker_log_config(
    environ: Mapping[str, str], worker_name: str, data_dir: str
) -> str:
    """Generate a log.config file for the given worker.

    Returns: the path to the generated file
    """
    # Check whether we should write worker logs to disk, in addition to the console
    extra_log_template_args: Dict[str, Optional[str]] = {}
    if environ.get("SYNAPSE_WORKERS_WRITE_LOGS_TO_DISK"):
        extra_log_template_args["LOG_FILE_PATH"] = f"{data_dir}/logs/{worker_name}.log"

    extra_log_template_args["SYNAPSE_LOG_LEVEL"] = environ.get("SYNAPSE_LOG_LEVEL")
    extra_log_template_args["SYNAPSE_LOG_SENSITIVE"] = environ.get(
        "SYNAPSE_LOG_SENSITIVE"
    )

    # Render and write the file
    log_config_filepath = f"/conf/workers/{worker_name}.log.config"
    convert(
        "/conf/log.config",
        log_config_filepath,
        worker_name=worker_name,
        **extra_log_template_args,
        include_worker_name_in_log_line=environ.get(
            "SYNAPSE_USE_EXPERIMENTAL_FORKING_LAUNCHER"
        ),
    )
    return log_config_filepath


def main(args: List[str], environ: MutableMapping[str, str]) -> None:
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
    else:
        log("Base homeserver config exists—not regenerating")
    # This script may be run multiple times (mostly by Complement, see note at top of
    # file). Don't re-configure workers in this instance.
    mark_filepath = "/conf/workers_have_been_configured"
    if not os.path.exists(mark_filepath):
        # Collect and validate worker_type requests
        # Read the desired worker configuration from the environment
        worker_types_env = environ.get("SYNAPSE_WORKER_TYPES", "").strip()
        # Only process worker_types if they exist
        if not worker_types_env:
            # No workers, just the main process
            worker_types = []
            requested_worker_types: Dict[str, Any] = {}
        else:
            # Split type names by comma, ignoring whitespace.
            worker_types = split_and_strip_string(worker_types_env, ",")
            requested_worker_types = parse_worker_types_from_env(worker_types)

        # Always regenerate all other config files
        log("Generating worker config files")
        generate_worker_files(environ, config_path, data_dir, requested_worker_types)

        # Mark workers as being configured
        with open(mark_filepath, "w") as f:
            f.write("")
    else:
        log("Worker config exists—not regenerating")

    # Lifted right out of start.py
    jemallocpath = "/usr/lib/%s-linux-gnu/libjemalloc.so.2" % (platform.machine(),)

    if os.path.isfile(jemallocpath):
        environ["LD_PRELOAD"] = jemallocpath
    else:
        log("Could not find %s, will not use" % (jemallocpath,))

    # Start supervisord, which will start Synapse, all of the configured worker
    # processes, redis, nginx etc. according to the config we created above.
    log("Starting supervisord")
    flush_buffers()
    os.execle(
        "/usr/local/bin/supervisord",
        "supervisord",
        "-c",
        "/etc/supervisor/supervisord.conf",
        environ,
    )


if __name__ == "__main__":
    main(sys.argv, os.environ)
