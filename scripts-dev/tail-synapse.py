import collections
import json
import sys
import time

import requests

Entry = collections.namedtuple("Entry", "name position rows")

ROW_TYPES = {}


def row_type_for_columns(name, column_names):
    column_names = tuple(column_names)
    row_type = ROW_TYPES.get((name, column_names))
    if row_type is None:
        row_type = collections.namedtuple(name, column_names)
        ROW_TYPES[(name, column_names)] = row_type
    return row_type


def parse_response(content):
    streams = json.loads(content)
    result = {}
    for name, value in streams.items():
        row_type = row_type_for_columns(name, value["field_names"])
        position = value["position"]
        rows = [row_type(*row) for row in value["rows"]]
        result[name] = Entry(name, position, rows)
    return result


def replicate(server, streams):
    return parse_response(
        requests.get(
            server + "/_synapse/replication", verify=False, params=streams
        ).content
    )


def main():
    server = sys.argv[1]

    streams = None
    while not streams:
        try:
            streams = {
                row.name: row.position
                for row in replicate(server, {"streams": "-1"})["streams"].rows
            }
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)

    while True:
        try:
            results = replicate(server, streams)
        except Exception:
            sys.stdout.write("connection_lost(" + repr(streams) + ")\n")
            break
        for update in results.values():
            for row in update.rows:
                sys.stdout.write(repr(row) + "\n")
            streams[update.name] = update.position


if __name__ == "__main__":
    main()
