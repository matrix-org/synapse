import json
from time import monotonic

import requests

HOMESERVER = "http://localhost:8080"

USER_1_TOK = "syt_dGVzdGVy_AywuFarQjsYrHuPkOUvg_25XLNK"
USER_1_HEADERS = {"Authorization": f"Bearer {USER_1_TOK}"}

USER_2_TOK = "syt_b3RoZXI_jtiTnwtlBjMGMixlHIBM_4cxesB"
USER_2_HEADERS = {"Authorization": f"Bearer {USER_2_TOK}"}


def _check_for_status(result):
    # Similar to raise_for_status, but prints the error.
    if 400 <= result.status_code:
        error_msg = result.json()
        print(error_msg)
        exit(0)


def _sync_and_show(room_id):
    print("Syncing . . .")
    result = requests.get(
        f"{HOMESERVER}/_matrix/client/v3/sync",
        headers=USER_1_HEADERS,
        params={
            "filter": json.dumps(
                {
                    "room": {
                        "timeline": {"limit": 30, "unread_thread_notifications": True}
                    }
                }
            )
        },
    )
    _check_for_status(result)
    sync_response = result.json()

    room = sync_response["rooms"]["join"][room_id]

    # Find read receipts (this assumes non-overlapping).
    read_receipts = {}  # thread -> event ID -> users
    for event in room["ephemeral"]["events"]:
        if event["type"] != "m.receipt":
            continue

        for event_id, content in event["content"].items():
            for mxid, receipt in content["m.read"].items():
                print(mxid, receipt)
                # Just care about the localpart of the MXID.
                mxid = mxid.split(":", 1)[0]
                read_receipts.setdefault(receipt.get("thread_id"), {}).setdefault(
                    event_id, []
                ).append(mxid)

    print(room["unread_notifications"])
    print(room.get("unread_thread_notifications"))
    print()

    # Convert events to their threads.
    threads = {}
    for event in room["timeline"]["events"]:
        if event["type"] != "m.room.message":
            continue

        event_id = event["event_id"]

        parent_id = event["content"].get("m.relates_to", {}).get("event_id")
        if parent_id:
            threads[parent_id][1].append(event)
        else:
            threads[event_id] = (event, [])

    for root_event_id, (root, thread) in threads.items():
        msg = root["content"]["body"]
        print(f"{root_event_id}: {msg}")

        for event in thread:
            thread_event_id = event["event_id"]

            msg = event["content"]["body"]
            print(f"\t{thread_event_id}: {msg}")

            if thread_event_id in read_receipts.get(root_event_id, {}):
                user_ids = ", ".join(read_receipts[root_event_id][thread_event_id])
                print(f"\t^--------- {user_ids} ---------^")

        if root_event_id in read_receipts[None]:
            user_ids = ", ".join(read_receipts[None][root_event_id])
            print(f"^--------- {user_ids} ---------^")

    print()
    print()


def _send_event(room_id, body, thread_id=None):
    content = {
        "msgtype": "m.text",
        "body": body,
    }
    if thread_id:
        content["m.relates_to"] = {
            "rel_type": "m.thread",
            "event_id": thread_id,
        }

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
        json={"visibility": "public", "name": f"Thread Read Receipts ({monotonic()})"},
        headers=USER_2_HEADERS,
    )
    _check_for_status(result)
    room_id = result.json()["room_id"]

    # Second user joins the room.
    result = requests.post(
        f"{HOMESERVER}/_matrix/client/v3/rooms/{room_id}/join", headers=USER_1_HEADERS
    )
    _check_for_status(result)

    # Sync user 1.
    _sync_and_show(room_id)

    # User 2 sends some messages.
    event_ids = []

    def _send_and_append(body, thread_id=None):
        event_id = _send_event(room_id, body, thread_id)
        event_ids.append(event_id)
        return event_id

    for msg in range(5):
        root_message_id = _send_and_append(f"Message {msg}")
    for msg in range(10):
        if msg % 2:
            _send_and_append(f"More message {msg}")
        else:
            _send_and_append(f"Thread Message {msg}", root_message_id)

    # User 2 sends a read receipt.
    print("@second reads main timeline")
    result = requests.post(
        f"{HOMESERVER}/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event_ids[3]}",
        headers=USER_2_HEADERS,
        json={},
    )
    _check_for_status(result)

    _sync_and_show(room_id)

    # User 1 sends a read receipt.
    print("@test reads main timeline")
    result = requests.post(
        f"{HOMESERVER}/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event_ids[-5]}",
        headers=USER_1_HEADERS,
        json={},
    )
    _check_for_status(result)

    _sync_and_show(room_id)

    # User 1 sends another read receipt.
    print("@test reads thread")
    result = requests.post(
        f"{HOMESERVER}/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event_ids[-4]}",
        headers=USER_1_HEADERS,
        json={"thread_id": root_message_id},
    )
    _check_for_status(result)

    _sync_and_show(room_id)


if __name__ == "__main__":
    main()
