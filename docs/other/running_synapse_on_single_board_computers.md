## Summary of performance impact of running on resource constrained devices such as SBCs

I've been running my homeserver on a cubietruck at home now for some time and am often replying to statements like "you need loads of ram to join large rooms" with "it works fine for me". I thought it might be useful to curate a summary of the issues you're likely to run into to help as a scaling-down guide, maybe highlight these for development work or end up as documentation. It seems that once you get up to about 4x1.5GHz arm64 4GiB these issues are no longer a problem.

- **Platform**: 2x1GHz armhf 2GiB ram [Single-board computers](https://wiki.debian.org/CheapServerBoxHardware), SSD, postgres.

### Presence

This is the main reason people have a poor matrix experience on resource constrained homeservers. Element web will frequently be saying the server is offline while the python process will be pegged at 100% cpu. This feature is used to tell when other users are active (have a client app in the foreground) and therefore more likely to respond, but requires a lot of network activity to maintain even when nobody is talking in a room.

![Screenshot_2020-10-01_19-29-46](https://user-images.githubusercontent.com/71895/94848963-a47a3580-041c-11eb-8b6e-acb772b4259e.png)

While synapse does have some performance issues with presence [#3971](https://github.com/matrix-org/synapse/issues/3971), the fundamental problem is that this is an easy feature to implement for a centralised service at nearly no overhead, but federation makes it combinatorial [#8055](https://github.com/matrix-org/synapse/issues/8055). There is also a client-side config option which disables the UI and idle tracking [enable_presence_by_hs_url] to blacklist the largest instances but I didn't notice much difference, so I recommend disabling the feature entirely at the server level as well.

[enable_presence_by_hs_url]: https://github.com/vector-im/element-web/blob/v1.7.8/config.sample.json#L45

### Joining

Joining a "large", federated room will initially fail with the below message in Element web, but waiting a while (10-60mins) and trying again will succeed without any issue. What counts as "large" is not message history, user count, connections to homeservers or even a simple count of the state events, it is instead how long the state resolution algorithm takes. However, each of those numbers are reasonable proxies, so we can use them as estimates since user count is one of the few things you see before joining.

![Screenshot_2020-10-02_17-15-06](https://user-images.githubusercontent.com/71895/94945781-18771500-04d3-11eb-8419-83c2da73a341.png)

This is [#1211](https://github.com/matrix-org/synapse/issues/1211) and will also hopefully be mitigated by peeking [matrix-org/matrix-doc#2753](https://github.com/matrix-org/matrix-doc/pull/2753) so at least you don't need to wait for a join to complete before finding out if it's the kind of room you want. Note that you should first disable presence, otherwise it'll just make the situation worse [#3120](https://github.com/matrix-org/synapse/issues/3120). There is a lot of database interaction too, so make sure you've [migrated your data](../postgres.md) from the default sqlite to postgresql. Personally, I recommend patience - once the initial join is complete there's rarely any issues with actually interacting with the room, but if you like you can just block "large" rooms entirely.

### Sessions

Anything that requires modifying the device list [#7721](https://github.com/matrix-org/synapse/issues/7721) will take a while to propagate, again taking the client "Offline" until it's complete. This includes signing in and out, editing the public name and verifying e2ee. The main mitigation I recommend is to keep long-running sessions open e.g. by using Firefox SSB "Use this site in App mode" or Chromium PWA "Install Element".

### Recommended configuration

Put the below in a new file at /etc/matrix-synapse/conf.d/sbc.yaml to override the defaults in homeserver.yaml.

```
# Disable presence tracking, which is currently fairly resource intensive
# More info: https://github.com/matrix-org/synapse/issues/9478
use_presence: false

# Set a small complexity limit, preventing users from joining large rooms
# which may be resource-intensive to remain a part of.
#
# Note that this will not prevent users from joining smaller rooms that
# eventually become complex.
limit_remote_rooms:
  enabled: true
  complexity: 3.0

# Database configuration
database:
  # Use postgres for the best performance
  name: psycopg2
  args:
    user: matrix-synapse
    # Generate a long, secure password using a password manager
    password: hunter2
    database: matrix-synapse
    host: localhost
```

Currently the complexity is measured by [current_state_events / 500](https://github.com/matrix-org/synapse/blob/v1.20.1/synapse/storage/databases/main/events_worker.py#L986). You can find join times and your most complex rooms like this:

```
admin@homeserver:~$ zgrep '/client/r0/join/' /var/log/matrix-synapse/homeserver.log* | awk '{print $18, $25}' | sort --human-numeric-sort
29.922sec/-0.002sec /_matrix/client/r0/join/%23debian-fasttrack%3Apoddery.com
182.088sec/0.003sec /_matrix/client/r0/join/%23decentralizedweb-general%3Amatrix.org
911.625sec/-570.847sec /_matrix/client/r0/join/%23synapse%3Amatrix.org

admin@homeserver:~$ sudo --user postgres psql matrix-synapse --command 'select canonical_alias, joined_members, current_state_events from room_stats_state natural join room_stats_current where canonical_alias is not null order by current_state_events desc fetch first 5 rows only'
        canonical_alias        | joined_members | current_state_events 
-------------------------------+----------------+----------------------
 #_oftc_#debian:matrix.org             |  871   |  52355
 #matrix:matrix.org                    |  6379  |  10684
 #irc:matrix.org                       |  461   |  3751
 #decentralizedweb-general:matrix.org  |  997   |  1509
 #whatsapp:maunium.net                 |  554   |  854
```