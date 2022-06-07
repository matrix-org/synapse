import json
from time import monotonic, sleep

import requests


HOMESERVER = "http://localhost:8080"

USER_1_TOK = "syt_dGVzdA_JUXtKQUUMnolcOezckNz_2eyt3H"
USER_1_HEADERS = {"Authorization": f"Bearer {USER_1_TOK}"}

USER_2_TOK = "syt_c2Vjb25k_ElKwbhaNqTgpfgFQcStD_2aiOcs"
USER_2_HEADERS = {"Authorization": f"Bearer {USER_2_TOK}"}


def _check_for_status(result):
    # Similar to raise_for_status, but prints the error.
    if 400 <= result.status_code:
        error_msg = result.json()
        result.raise_for_status()
        print(error_msg)
        exit(0)


def _send_event(room_id, content):
    # Send a msg to the room.
    result = requests.put(
        f"{HOMESERVER}/_matrix/client/v3/rooms/{room_id}/send/m.room.message/msg{monotonic()}",
        json=content,
        headers=USER_2_HEADERS,
    )
    _check_for_status(result)
    return result.json()["event_id"]


def main():
    # Create a new room as user 2, add a bunch of messages.
    result = requests.post(
        f"{HOMESERVER}/_matrix/client/v3/createRoom",
        json={"visibility": "public", "name": f"Ranged Read Receipts ({monotonic()})"},
        headers=USER_2_HEADERS,
    )
    _check_for_status(result)
    room_id = result.json()["room_id"]

    # Second user joins the room.
    result = requests.post(
        f"{HOMESERVER}/_matrix/client/v3/rooms/{room_id}/join", headers=USER_1_HEADERS
    )
    _check_for_status(result)

    # User 2 sends some messages.
    thread_event_id = None

    def _send(body, thread_id = None):
        content = {
            "msgtype": "m.text",
            "body": body,
        }
        if thread_id:
            content["m.relates_to"] = {
                "rel_type": "m.thread",
                "event_id": thread_id,
            }
        return _send_event(room_id, content)

    for msg in range(10):
        event_id = _send(f"Message {msg}")
        if msg % 5 == 0:
            sleep(3)
    thread_event_id = event_id

    for msg in range(60):
        if msg % 3 == 0:
            _send(f"More message {msg}")
        else:
            _send(f"Thread message {msg}", thread_event_id)

        if msg % 5 == 0:
            sleep(3)


if __name__ == "__main__":
    main()
