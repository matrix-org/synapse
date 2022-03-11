import json
import time
from synapse.api.room_versions import RoomVersion, RoomVersions

from synapse.events import make_event_from_dict

import synapse_events

with open("/home/erikj/git/synapse/hq_events", "rb") as f:
    event_json = f.readlines()

start = time.time()

rust_events = []

for e in event_json:
    e = e.strip()
    e = e.replace(b"\\\\", b"\\")
    event = synapse_events.from_bytes(e)
    rust_events.append(event)

now = time.time()

print(f"Parsed rust event in {now - start:.2f} seconds")

event_dicts = []

start = time.time()

event_dicts = []
for e in event_json:
    e = e.strip()
    e = e.replace(b"\\\\", b"\\")
    event_dicts.append(json.loads(e.strip()))

now = time.time()

print(f"Parsed JSON in {now - start:.2f} seconds")

events = []

start = time.time()

for e in event_dicts:
    event = make_event_from_dict(e, RoomVersions.V5)
    events.append(event)

now = time.time()

print(f"Parsed event in {now - start:.2f} seconds")
