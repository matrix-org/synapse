#!/usr/bin/env python
# Copyright 2022 The Matrix.org Foundation C.I.C.
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
import dataclasses
import sys
from os.path import dirname
from pathlib import Path
from typing import List, Tuple, Iterable

from jinja2 import Environment, FileSystemLoader
from signedjson.key import generate_signing_key, write_signing_keys

from synapse.util.stringutils import random_string

DESIRED_WORKERS = (
    ("main", 1),
    ("synchrotron", 2),
    ("federation_inbound", 2),
    ("federation_reader", 2),
    ("federation_sender", 2),
    ("typing", 1),
    ("appservice", 1),
    ("client_reader", 2),
    ("event_creator", 2),
    ("event_persister", 2),
    ("media_repository", 1),
    ("pusher", 2),
    ("user_dir", 1),
    ("background_worker", 1),
    # TODO ("encryption", 1),  # ??
    ("receipts_account_data", 1)
    # TODO frontend_proxy?
)


@dataclasses.dataclass
class Worker:
    name: str
    kind: str
    index: int
    ip: str


def worker_num_to_ip(num: int) -> str:
    return f"127.0.57.{num}"


def make_workers(workers: Iterable[Tuple[str, int]]) -> List[Worker]:
    result = []
    worker_overall_num = 0
    for worker_type, worker_type_count in workers:
        for worker_idx in range(1, worker_type_count + 1):
            worker_overall_num += 1
            if worker_type == "main":
                worker_name = "main"
            else:
                worker_name = f"{worker_type}{worker_idx}"

            result.append(Worker(
                worker_name, worker_type, worker_idx, worker_num_to_ip(worker_overall_num)
            ))

    return result


def generate(worker_counts: Tuple[Tuple[str, int], ...], target_path: Path, server_name: str) -> None:
    if target_path.exists():
        print("Target path already exists. Won't overwrite.")
        return
    target_path.mkdir()

    # Generate a signing key
    key_id = "a_" + random_string(4)
    key = (generate_signing_key(key_id),)
    with open(target_path.joinpath("signing.key"), "w") as fout:
        write_signing_keys(fout, key)

    macaroon_secret_key = random_string(32)

    env = Environment(loader=FileSystemLoader(dirname(__file__) + "/workers_setup"))
    hs_template = env.get_template("homeserver.yaml.j2")
    worker_template = env.get_template("worker.yaml.j2")
    logging_template = env.get_template("logging.yaml.j2")

    worker_dir = target_path.joinpath("workers")
    worker_dir.mkdir()
    worker_logging_dir = target_path.joinpath("workers.logging")
    worker_logging_dir.mkdir()
    worker_dir = worker_dir.resolve()

    logs_dir = target_path.joinpath("logs")
    logs_dir.mkdir()
    logs_dir = logs_dir.resolve()

    all_workers = make_workers(worker_counts)
    workers_by_name = {worker.name: worker for worker in all_workers}

    for worker in all_workers:
        log_config_path = worker_logging_dir.joinpath(f"{worker.name}.logging.yaml")
        log_config = logging_template.render(
            worker=worker,
            worker_dir=worker_dir,
            logs_dir=logs_dir,
            all_workers=all_workers,
            workers_by_name=workers_by_name
        )
        with open(log_config_path, "w") as fout:
            fout.write(log_config)

        if worker.name == "main":
            # Main can't use a worker file.
            continue

        worker_config_path = worker_dir.joinpath(f"{worker.name}.yaml")
        worker_config = worker_template.render(
            worker=worker,
            worker_dir=worker_dir,
            logs_dir=logs_dir,
            all_workers=all_workers,
            workers_by_name=workers_by_name
        )
        with open(worker_config_path, "w") as fout:
            fout.write(worker_config)

    hs_config_path = target_path.joinpath("homeserver.yaml")
    hs_config = hs_template.render(
        all_workers=all_workers,
        worker_dir=worker_dir,
        logs_dir=logs_dir,
        server_name=server_name,
        macaroon_secret_key=macaroon_secret_key
    )
    with open(hs_config_path, "w") as fout:
        fout.write(hs_config)


def main(target_path: Path, server_name: str) -> None:
    generate(DESIRED_WORKERS, target_path, server_name)


if __name__ == '__main__':
    target_path = Path(sys.argv[1])
    server_name = sys.argv[2]
    main(target_path, server_name)
