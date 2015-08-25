import psycopg2
import yaml
import sys
import json
import time
import hashlib
from unpaddedbase64 import encode_base64
from signedjson.key import read_signing_keys
from signedjson.sign import sign_json
from canonicaljson import encode_canonical_json


def select_v1_keys(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT server_name, key_id, verify_key FROM server_signature_keys")
    rows = cursor.fetchall()
    cursor.close()
    results = {}
    for server_name, key_id, verify_key in rows:
        results.setdefault(server_name, {})[key_id] = encode_base64(verify_key)
    return results


def select_v1_certs(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT server_name, tls_certificate FROM server_tls_certificates")
    rows = cursor.fetchall()
    cursor.close()
    results = {}
    for server_name, tls_certificate in rows:
        results[server_name] = tls_certificate
    return results


def select_v2_json(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT server_name, key_id, key_json FROM server_keys_json")
    rows = cursor.fetchall()
    cursor.close()
    results = {}
    for server_name, key_id, key_json in rows:
        results.setdefault(server_name, {})[key_id] = json.loads(str(key_json).decode("utf-8"))
    return results


def convert_v1_to_v2(server_name, valid_until, keys, certificate):
    return {
        "old_verify_keys": {},
        "server_name": server_name,
        "verify_keys": {
            key_id: {"key": key}
            for key_id, key in keys.items()
        },
        "valid_until_ts": valid_until,
        "tls_fingerprints": [fingerprint(certificate)],
    }


def fingerprint(certificate):
    finger = hashlib.sha256(certificate)
    return {"sha256": encode_base64(finger.digest())}


def rows_v2(server, json):
    valid_until = json["valid_until_ts"]
    key_json = encode_canonical_json(json)
    for key_id in json["verify_keys"]:
        yield (server, key_id, "-", valid_until, valid_until, buffer(key_json))


def main():
    config = yaml.load(open(sys.argv[1]))
    valid_until = int(time.time() / (3600 * 24)) * 1000 * 3600 * 24

    server_name = config["server_name"]
    signing_key = read_signing_keys(open(config["signing_key_path"]))[0]

    database = config["database"]
    assert database["name"] == "psycopg2", "Can only convert for postgresql"
    args = database["args"]
    args.pop("cp_max")
    args.pop("cp_min")
    connection = psycopg2.connect(**args)
    keys = select_v1_keys(connection)
    certificates = select_v1_certs(connection)
    json = select_v2_json(connection)

    result = {}
    for server in keys:
        if not server in json:
            v2_json = convert_v1_to_v2(
                server, valid_until, keys[server], certificates[server]
            )
            v2_json = sign_json(v2_json, server_name, signing_key)
            result[server] = v2_json

    yaml.safe_dump(result, sys.stdout, default_flow_style=False)

    rows = list(
        row for server, json in result.items()
        for row in rows_v2(server, json)
    )

    cursor = connection.cursor()
    cursor.executemany(
        "INSERT INTO server_keys_json ("
        " server_name, key_id, from_server,"
        " ts_added_ms, ts_valid_until_ms, key_json"
        ") VALUES (%s, %s, %s, %s, %s, %s)",
        rows
    )
    connection.commit()


if __name__ == '__main__':
    main()
