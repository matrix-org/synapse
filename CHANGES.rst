Changes in synapse v0.20.0-rc1 (2017-03-30)
===========================================

Features:

* Add delete_devices API (PR #1993)
* Add phone number registration/login support (PR #1994, #2055)


Changes:

* Use JSONSchema for validation of filters. Thanks @pik! (PR #1783)
* Reread log config on SIGHUP (PR #1982)
* Speed up public room list (PR #1989)
* Add helpful texts to logger config options (PR #1990)
* Minor ``/sync`` performance improvements. (PR #2002, #2013, #2022)
* Add some debug to help diagnose weird federation issue (PR #2035)
* Correctly limit retries for all federation requests (PR #2050, #2061)
* Don't lock table when persisting new one time keys (PR #2053)
* Reduce some CPU work on DB threads (PR #2054)
* Cache hosts in room (PR #2060)
* Batch sending of device list pokes (PR #2063)
* Speed up persist event path in certain edge cases (PR #2070)


Bug fixes:

* Fix bug where current_state_events renamed to current_state_ids (PR #1849)
* Fix routing loop when fetching remote media (PR #1992)
* Fix current_state_events table to not lie (PR #1996)
* Fix CAS login to handle PartialDownloadError (PR #1997)
* Fix assertion to stop transaction queue getting wedged (PR #2010)
* Fix presence to fallback to last_active_ts if it beats the last sync time.
  Thanks @Half-Shot! (PR #2014)
* Fix bug when federation received a PDU while a room join is in progress (PR
  #2016)
* Fix resetting state on rejected events (PR #2025)
* Fix installation issues in readme. Thanks @ricco386 (PR #2037)
* Fix caching of remote servers' signature keys (PR #2042)
* Fix some leaking log context (PR #2048, #2049, #2057, #2058)
* Fix rejection of invites not reaching sync (PR #2056)



Changes in synapse v0.19.3 (2017-03-20)
=======================================

No changes since v0.19.3-rc2


Changes in synapse v0.19.3-rc2 (2017-03-13)
===========================================

Bug fixes:

* Fix bug in handling of incoming device list updates over federation.



Changes in synapse v0.19.3-rc1 (2017-03-08)
===========================================

Features:

* Add some administration functionalities. Thanks to morteza-araby! (PR #1784)


Changes:

* Reduce database table sizes (PR #1873, #1916, #1923, #1963)
* Update contrib/ to not use syutil. Thanks to andrewshadura! (PR #1907)
* Don't fetch current state when sending an event in common case (PR #1955)


Bug fixes:

* Fix synapse_port_db failure. Thanks to Pneumaticat! (PR #1904)
* Fix caching to not cache error responses (PR #1913)
* Fix APIs to make kick & ban reasons work (PR #1917)
* Fix bugs in the /keys/changes api (PR #1921)
* Fix bug where users couldn't forget rooms they were banned from (PR #1922)
* Fix issue with long language values in pushers API (PR #1925)
* Fix a race in transaction queue (PR #1930)
* Fix dynamic thumbnailing to preserve aspect ratio. Thanks to jkolo! (PR
  #1945)
* Fix device list update to not constantly resync (PR #1964)
* Fix potential for huge memory usage when getting device that have
  changed (PR #1969)



Changes in synapse v0.19.2 (2017-02-20)
=======================================

* Fix bug with event visibility check in /context/ API. Thanks to Tokodomo for
  pointing it out! (PR #1929)


Changes in synapse v0.19.1 (2017-02-09)
=======================================

* Fix bug where state was incorrectly reset in a room when synapse received an
  event over federation that did not pass auth checks (PR #1892)


Changes in synapse v0.19.0 (2017-02-04)
=======================================

No changes since RC 4.


Changes in synapse v0.19.0-rc4 (2017-02-02)
===========================================

* Bump cache sizes for common membership queries (PR #1879)


Changes in synapse v0.19.0-rc3 (2017-02-02)
===========================================

* Fix email push in pusher worker (PR #1875)
* Make presence.get_new_events a bit faster (PR #1876)
* Make /keys/changes a bit more performant (PR #1877)


Changes in synapse v0.19.0-rc2 (2017-02-02)
===========================================

* Include newly joined users in /keys/changes API (PR #1872)


Changes in synapse v0.19.0-rc1 (2017-02-02)
===========================================

Features:

* Add support for specifying multiple bind addresses (PR #1709, #1712, #1795,
  #1835). Thanks to @kyrias!
* Add /account/3pid/delete endpoint (PR #1714)
* Add config option to configure the Riot URL used in notification emails (PR
  #1811). Thanks to @aperezdc!
* Add username and password config options for turn server (PR #1832). Thanks
  to @xsteadfastx!
* Implement device lists updates over federation (PR #1857, #1861, #1864)
* Implement /keys/changes (PR #1869, #1872)


Changes:

* Improve IPv6 support (PR #1696). Thanks to @kyrias and @glyph!
* Log which files we saved attachments to in the media_repository (PR #1791)
* Linearize updates to membership via PUT /state/ to better handle multiple
  joins (PR #1787)
* Limit number of entries to prefill from cache on startup (PR #1792)
* Remove full_twisted_stacktraces option (PR #1802)
* Measure size of some caches by sum of the size of cached values (PR #1815)
* Measure metrics of string_cache (PR #1821)
* Reduce logging verbosity (PR #1822, #1823, #1824)
* Don't clobber a displayname or avatar_url if provided by an m.room.member
  event (PR #1852)
* Better handle 401/404 response for federation /send/ (PR #1866, #1871)


Fixes:

* Fix ability to change password to a non-ascii one (PR #1711)
* Fix push getting stuck due to looking at the wrong view of state (PR #1820)
* Fix email address comparison to be case insensitive (PR #1827)
* Fix occasional inconsistencies of room membership (PR #1836, #1840)


Performance:

* Don't block messages sending on bumping presence (PR #1789)
* Change device_inbox stream index to include user (PR #1793)
* Optimise state resolution (PR #1818)
* Use DB cache of joined users for presence (PR #1862)
* Add an index to make membership queries faster (PR #1867)


Changes in synapse v0.18.7 (2017-01-09)
=======================================

No changes from v0.18.7-rc2


Changes in synapse v0.18.7-rc2 (2017-01-07)
===========================================

Bug fixes:

* Fix error in rc1's discarding invalid inbound traffic logic that was
  incorrectly discarding missing events


Changes in synapse v0.18.7-rc1 (2017-01-06)
===========================================

Bug fixes:

* Fix error in #PR 1764 to actually fix the nightmare #1753 bug.
* Improve deadlock logging further
* Discard inbound federation traffic from invalid domains, to immunise
  against #1753


Changes in synapse v0.18.6 (2017-01-06)
=======================================

Bug fixes:

* Fix bug when checking if a guest user is allowed to join a room (PR #1772)
  Thanks to Patrik Oldsberg for diagnosing and the fix!


Changes in synapse v0.18.6-rc3 (2017-01-05)
===========================================

Bug fixes:

* Fix bug where we failed to send ban events to the banned server (PR #1758)
* Fix bug where we sent event that didn't originate on this server to
  other servers (PR #1764)
* Fix bug where processing an event from a remote server took a long time
  because we were making long HTTP requests (PR #1765, PR #1744)

Changes:

* Improve logging for debugging deadlocks (PR #1766, PR #1767)


Changes in synapse v0.18.6-rc2 (2016-12-30)
===========================================

Bug fixes:

* Fix memory leak in twisted by initialising logging correctly (PR #1731)
* Fix bug where fetching missing events took an unacceptable amount of time in
  large rooms (PR #1734)


Changes in synapse v0.18.6-rc1 (2016-12-29)
===========================================

Bug fixes:

* Make sure that outbound connections are closed (PR #1725)


Changes in synapse v0.18.5 (2016-12-16)
=======================================

Bug fixes:

* Fix federation /backfill returning events it shouldn't (PR #1700)
* Fix crash in url preview (PR #1701)


Changes in synapse v0.18.5-rc3 (2016-12-13)
===========================================

Features:

* Add support for E2E for guests (PR #1653)
* Add new API appservice specific public room list (PR #1676)
* Add new room membership APIs (PR #1680)


Changes:

* Enable guest access for private rooms by default (PR #653)
* Limit the number of events that can be created on a given room concurrently
  (PR #1620)
* Log the args that we have on UI auth completion (PR #1649)
* Stop generating refresh_tokens (PR #1654)
* Stop putting a time caveat on access tokens (PR #1656)
* Remove unspecced GET endpoints for e2e keys (PR #1694)


Bug fixes:

* Fix handling of 500 and 429's over federation (PR #1650)
* Fix Content-Type header parsing (PR #1660)
* Fix error when previewing sites that include unicode, thanks to kyrias (PR
  #1664)
* Fix some cases where we drop read receipts (PR #1678)
* Fix bug where calls to ``/sync`` didn't correctly timeout (PR #1683)
* Fix bug where E2E key query would fail if a single remote host failed (PR
  #1686)



Changes in synapse v0.18.5-rc2 (2016-11-24)
===========================================

Bug fixes:

* Don't send old events over federation, fixes bug in -rc1.

Changes in synapse v0.18.5-rc1 (2016-11-24)
===========================================

Features:

* Implement "event_fields" in filters (PR #1638)

Changes:

* Use external ldap auth pacakge (PR #1628)
* Split out federation transaction sending to a worker (PR #1635)
* Fail with a coherent error message if `/sync?filter=` is invalid (PR #1636)
* More efficient notif count queries (PR #1644)


Changes in synapse v0.18.4 (2016-11-22)
=======================================

Bug fixes:

* Add workaround for buggy clients that the fail to register (PR #1632)


Changes in synapse v0.18.4-rc1 (2016-11-14)
===========================================

Changes:

* Various database efficiency improvements (PR #1188, #1192)
* Update default config to blacklist more internal IPs, thanks to Euan Kemp (PR
  #1198)
* Allow specifying duration in minutes in config, thanks to Daniel Dent (PR
  #1625)


Bug fixes:

* Fix media repo to set CORs headers on responses (PR #1190)
* Fix registration to not error on non-ascii passwords (PR #1191)
* Fix create event code to limit the number of prev_events (PR #1615)
* Fix bug in transaction ID deduplication (PR #1624)


Changes in synapse v0.18.3 (2016-11-08)
=======================================

SECURITY UPDATE

Explicitly require authentication when using LDAP3. This is the default on
versions of ``ldap3`` above 1.0, but some distributions will package an older
version.

If you are using LDAP3 login and have a version of ``ldap3`` older than 1.0 it
is **CRITICAL to updgrade**.


Changes in synapse v0.18.2 (2016-11-01)
=======================================

No changes since v0.18.2-rc5


Changes in synapse v0.18.2-rc5 (2016-10-28)
===========================================

Bug fixes:

* Fix prometheus process metrics in worker processes (PR #1184)


Changes in synapse v0.18.2-rc4 (2016-10-27)
===========================================

Bug fixes:

* Fix ``user_threepids`` schema delta, which in some instances prevented
  startup after upgrade (PR #1183)


Changes in synapse v0.18.2-rc3 (2016-10-27)
===========================================

Changes:

* Allow clients to supply access tokens as headers (PR #1098)
* Clarify error codes for GET /filter/, thanks to Alexander Maznev (PR #1164)
* Make password reset email field case insensitive (PR #1170)
* Reduce redundant database work in email pusher (PR #1174)
* Allow configurable rate limiting per AS (PR #1175)
* Check whether to ratelimit sooner to avoid work (PR #1176)
* Standardise prometheus metrics (PR #1177)


Bug fixes:

* Fix incredibly slow back pagination query (PR #1178)
* Fix infinite typing bug (PR #1179)


Changes in synapse v0.18.2-rc2 (2016-10-25)
===========================================

(This release did not include the changes advertised and was identical to RC1)


Changes in synapse v0.18.2-rc1 (2016-10-17)
===========================================

Changes:

* Remove redundant event_auth index (PR #1113)
* Reduce DB hits for replication (PR #1141)
* Implement pluggable password auth (PR #1155)
* Remove rate limiting from app service senders and fix get_or_create_user
  requester, thanks to Patrik Oldsberg (PR #1157)
* window.postmessage for Interactive Auth fallback (PR #1159)
* Use sys.executable instead of hardcoded python, thanks to Pedro Larroy
  (PR #1162)
* Add config option for adding additional TLS fingerprints (PR #1167)
* User-interactive auth on delete device (PR #1168)


Bug fixes:

* Fix not being allowed to set your own state_key, thanks to Patrik Oldsberg
  (PR #1150)
* Fix interactive auth to return 401 from for incorrect password (PR #1160,
  #1166)
* Fix email push notifs being dropped (PR #1169)



Changes in synapse v0.18.1 (2016-10-05)
======================================

No changes since v0.18.1-rc1


Changes in synapse v0.18.1-rc1 (2016-09-30)
===========================================

Features:

* Add total_room_count_estimate to ``/publicRooms`` (PR #1133)


Changes:

* Time out typing over federation (PR #1140)
* Restructure LDAP authentication (PR #1153)


Bug fixes:

* Fix 3pid invites when server is already in the room (PR #1136)
* Fix upgrading with SQLite taking lots of CPU for a few days
  after upgrade (PR #1144)
* Fix upgrading from very old database versions (PR #1145)
* Fix port script to work with recently added tables (PR #1146)


Changes in synapse v0.18.0 (2016-09-19)
=======================================

The release includes major changes to the state storage database schemas, which
significantly reduce database size. Synapse will attempt to upgrade the current
data in the background. Servers with large SQLite database may experience
degradation of performance while this upgrade is in progress, therefore you may
want to consider migrating to using Postgres before upgrading very large SQLite
databases


Changes:

* Make public room search case insensitive (PR #1127)


Bug fixes:

* Fix and clean up publicRooms pagination (PR #1129)


Changes in synapse v0.18.0-rc1 (2016-09-16)
===========================================

Features:

* Add ``only=highlight`` on ``/notifications`` (PR #1081)
* Add server param to /publicRooms (PR #1082)
* Allow clients to ask for the whole of a single state event (PR #1094)
* Add is_direct param to /createRoom (PR #1108)
* Add pagination support to publicRooms (PR #1121)
* Add very basic filter API to /publicRooms (PR #1126)
* Add basic direct to device messaging support for E2E (PR #1074, #1084, #1104,
  #1111)


Changes:

* Move to storing state_groups_state as deltas, greatly reducing DB size (PR
  #1065)
* Reduce amount of state pulled out of the DB during common requests (PR #1069)
* Allow PDF to be rendered from media repo (PR #1071)
* Reindex state_groups_state after pruning (PR #1085)
* Clobber EDUs in send queue (PR #1095)
* Conform better to the CAS protocol specification (PR #1100)
* Limit how often we ask for keys from dead servers (PR #1114)


Bug fixes:

* Fix /notifications API when used with ``from`` param (PR #1080)
* Fix backfill when cannot find an event. (PR #1107)


Changes in synapse v0.17.3 (2016-09-09)
=======================================

This release fixes a major bug that stopped servers from handling rooms with
over 1000 members.


Changes in synapse v0.17.2 (2016-09-08)
=======================================

This release contains security bug fixes. Please upgrade.


No changes since v0.17.2-rc1


Changes in synapse v0.17.2-rc1 (2016-09-05)
===========================================

Features:

* Start adding store-and-forward direct-to-device messaging (PR #1046, #1050,
  #1062, #1066)


Changes:

* Avoid pulling the full state of a room out so often (PR #1047, #1049, #1063,
  #1068)
* Don't notify for online to online presence transitions. (PR #1054)
* Occasionally persist unpersisted presence updates (PR #1055)
* Allow application services to have an optional 'url' (PR #1056)
* Clean up old sent transactions from DB (PR #1059)


Bug fixes:

* Fix None check in backfill (PR #1043)
* Fix membership changes to be idempotent (PR #1067)
* Fix bug in get_pdu where it would sometimes return events with incorrect
  signature



Changes in synapse v0.17.1 (2016-08-24)
=======================================

Changes:

* Delete old received_transactions rows (PR #1038)
* Pass through user-supplied content in /join/$room_id (PR #1039)


Bug fixes:

* Fix bug with backfill (PR #1040)


Changes in synapse v0.17.1-rc1 (2016-08-22)
===========================================

Features:

* Add notification API (PR #1028)


Changes:

* Don't print stack traces when failing to get remote keys (PR #996)
* Various federation /event/ perf improvements (PR #998)
* Only process one local membership event per room at a time (PR #1005)
* Move default display name push rule (PR #1011, #1023)
* Fix up preview URL API. Add tests. (PR #1015)
* Set ``Content-Security-Policy`` on media repo (PR #1021)
* Make notify_interested_services faster (PR #1022)
* Add usage stats to prometheus monitoring (PR #1037)


Bug fixes:

* Fix token login (PR #993)
* Fix CAS login (PR #994, #995)
* Fix /sync to not clobber status_msg (PR #997)
* Fix redacted state events to include prev_content (PR #1003)
* Fix some bugs in the auth/ldap handler (PR #1007)
* Fix backfill request to limit URI length, so that remotes don't reject the
  requests due to path length limits (PR #1012)
* Fix AS push code to not send duplicate events (PR #1025)



Changes in synapse v0.17.0 (2016-08-08)
=======================================

This release contains significant security bug fixes regarding authenticating
events received over federation. PLEASE UPGRADE.

This release changes the LDAP configuration format in a backwards incompatible
way, see PR #843 for details.


Changes:

* Add federation /version API (PR #990)
* Make psutil dependency optional (PR #992)


Bug fixes:

* Fix URL preview API to exclude HTML comments in description (PR #988)
* Fix error handling of remote joins (PR #991)


Changes in synapse v0.17.0-rc4 (2016-08-05)
===========================================

Changes:

* Change the way we summarize URLs when previewing (PR #973)
* Add new ``/state_ids/`` federation API (PR #979)
* Speed up processing of ``/state/`` response (PR #986)

Bug fixes:

* Fix event persistence when event has already been partially persisted
  (PR #975, #983, #985)
* Fix port script to also copy across backfilled events (PR #982)


Changes in synapse v0.17.0-rc3 (2016-08-02)
===========================================

Changes:

* Forbid non-ASes from registering users whose names begin with '_' (PR #958)
* Add some basic admin API docs (PR #963)


Bug fixes:

* Send the correct host header when fetching keys (PR #941)
* Fix joining a room that has missing auth events (PR #964)
* Fix various push bugs (PR #966, #970)
* Fix adding emails on registration (PR #968)


Changes in synapse v0.17.0-rc2 (2016-08-02)
===========================================

(This release did not include the changes advertised and was identical to RC1)


Changes in synapse v0.17.0-rc1 (2016-07-28)
===========================================

This release changes the LDAP configuration format in a backwards incompatible
way, see PR #843 for details.


Features:

* Add purge_media_cache admin API (PR #902)
* Add deactivate account admin API (PR #903)
* Add optional pepper to password hashing (PR #907, #910 by KentShikama)
* Add an admin option to shared secret registration (breaks backwards compat)
  (PR #909)
* Add purge local room history API (PR #911, #923, #924)
* Add requestToken endpoints (PR #915)
* Add an /account/deactivate endpoint (PR #921)
* Add filter param to /messages. Add 'contains_url' to filter. (PR #922)
* Add device_id support to /login (PR #929)
* Add device_id support to /v2/register flow. (PR #937, #942)
* Add GET /devices endpoint (PR #939, #944)
* Add GET /device/{deviceId} (PR #943)
* Add update and delete APIs for devices (PR #949)


Changes:

* Rewrite LDAP Authentication against ldap3 (PR #843 by mweinelt)
* Linearize some federation endpoints based on (origin, room_id) (PR #879)
* Remove the legacy v0 content upload API. (PR #888)
* Use similar naming we use in email notifs for push (PR #894)
* Optionally include password hash in createUser endpoint (PR #905 by
  KentShikama)
* Use a query that postgresql optimises better for get_events_around (PR #906)
* Fall back to 'username' if 'user' is not given for appservice registration.
  (PR #927 by Half-Shot)
* Add metrics for psutil derived memory usage (PR #936)
* Record device_id in client_ips (PR #938)
* Send the correct host header when fetching keys (PR #941)
* Log the hostname the reCAPTCHA was completed on (PR #946)
* Make the device id on e2e key upload optional (PR #956)
* Add r0.2.0 to the "supported versions" list (PR #960)
* Don't include name of room for invites in push (PR #961)


Bug fixes:

* Fix substitution failure in mail template (PR #887)
* Put most recent 20 messages in email notif (PR #892)
* Ensure that the guest user is in the database when upgrading accounts
  (PR #914)
* Fix various edge cases in auth handling (PR #919)
* Fix 500 ISE when sending alias event without a state_key (PR #925)
* Fix bug where we stored rejections in the state_group, persist all
  rejections (PR #948)
* Fix lack of check of if the user is banned when handling 3pid invites
  (PR #952)
* Fix a couple of bugs in the transaction and keyring code (PR #954, #955)



Changes in synapse v0.16.1-r1 (2016-07-08)
==========================================

THIS IS A CRITICAL SECURITY UPDATE.

This fixes a bug which allowed users' accounts to be accessed by unauthorised
users.

Changes in synapse v0.16.1 (2016-06-20)
=======================================

Bug fixes:

* Fix assorted bugs in ``/preview_url`` (PR #872)
* Fix TypeError when setting unicode passwords (PR #873)


Performance improvements:

* Turn ``use_frozen_events`` off by default (PR #877)
* Disable responding with canonical json for federation (PR #878)


Changes in synapse v0.16.1-rc1 (2016-06-15)
===========================================

Features: None

Changes:

* Log requester for ``/publicRoom`` endpoints when possible (PR #856)
* 502 on ``/thumbnail`` when can't connect to remote server (PR #862)
* Linearize fetching of gaps on incoming events (PR #871)


Bugs fixes:

* Fix bug where rooms where marked as published by default (PR #857)
* Fix bug where joining room with an event with invalid sender (PR #868)
* Fix bug where backfilled events were sent down sync streams (PR #869)
* Fix bug where outgoing connections could wedge indefinitely, causing push
  notifications to be unreliable (PR #870)


Performance improvements:

* Improve ``/publicRooms`` performance(PR #859)


Changes in synapse v0.16.0 (2016-06-09)
=======================================

NB: As of v0.14 all AS config files must have an ID field.


Bug fixes:

* Don't make rooms published by default (PR #857)

Changes in synapse v0.16.0-rc2 (2016-06-08)
===========================================

Features:

* Add configuration option for tuning GC via ``gc.set_threshold`` (PR #849)

Changes:

* Record metrics about GC (PR #771, #847, #852)
* Add metric counter for number of persisted events (PR #841)

Bug fixes:

* Fix 'From' header in email notifications (PR #843)
* Fix presence where timeouts were not being fired for the first 8h after
  restarts (PR #842)
* Fix bug where synapse sent malformed transactions to AS's when retrying
  transactions (Commits 310197b, 8437906)

Performance improvements:

* Remove event fetching from DB threads (PR #835)
* Change the way we cache events (PR #836)
* Add events to cache when we persist them (PR #840)


Changes in synapse v0.16.0-rc1 (2016-06-03)
===========================================

Version 0.15 was not released. See v0.15.0-rc1 below for additional changes.

Features:

* Add email notifications for missed messages (PR #759, #786, #799, #810, #815,
  #821)
* Add a ``url_preview_ip_range_whitelist`` config param (PR #760)
* Add /report endpoint (PR #762)
* Add basic ignore user API (PR #763)
* Add an openidish mechanism for proving that you own a given user_id (PR #765)
* Allow clients to specify a server_name to avoid 'No known servers' (PR #794)
* Add secondary_directory_servers option to fetch room list from other servers
  (PR #808, #813)

Changes:

* Report per request metrics for all of the things using request_handler (PR
  #756)
* Correctly handle ``NULL`` password hashes from the database (PR #775)
* Allow receipts for events we haven't seen in the db (PR #784)
* Make synctl read a cache factor from config file (PR #785)
* Increment badge count per missed convo, not per msg (PR #793)
* Special case m.room.third_party_invite event auth to match invites (PR #814)


Bug fixes:

* Fix typo in event_auth servlet path (PR #757)
* Fix password reset (PR #758)


Performance improvements:

* Reduce database inserts when sending transactions (PR #767)
* Queue events by room for persistence (PR #768)
* Add cache to ``get_user_by_id`` (PR #772)
* Add and use ``get_domain_from_id`` (PR #773)
* Use tree cache for ``get_linearized_receipts_for_room`` (PR #779)
* Remove unused indices (PR #782)
* Add caches to ``bulk_get_push_rules*`` (PR #804)
* Cache ``get_event_reference_hashes`` (PR #806)
* Add ``get_users_with_read_receipts_in_room`` cache (PR #809)
* Use state to calculate ``get_users_in_room`` (PR #811)
* Load push rules in storage layer so that they get cached (PR #825)
* Make ``get_joined_hosts_for_room`` use get_users_in_room (PR #828)
* Poke notifier on next reactor tick (PR #829)
* Change CacheMetrics to be quicker (PR #830)


Changes in synapse v0.15.0-rc1 (2016-04-26)
===========================================

Features:

* Add login support for Javascript Web Tokens, thanks to Niklas Riekenbrauck
  (PR #671,#687)
* Add URL previewing support (PR #688)
* Add login support for LDAP, thanks to Christoph Witzany (PR #701)
* Add GET endpoint for pushers (PR #716)

Changes:

* Never notify for member events (PR #667)
* Deduplicate identical ``/sync`` requests (PR #668)
* Require user to have left room to forget room (PR #673)
* Use DNS cache if within TTL (PR #677)
* Let users see their own leave events (PR #699)
* Deduplicate membership changes (PR #700)
* Increase performance of pusher code (PR #705)
* Respond with error status 504 if failed to talk to remote server (PR #731)
* Increase search performance on postgres (PR #745)

Bug fixes:

* Fix bug where disabling all notifications still resulted in push (PR #678)
* Fix bug where users couldn't reject remote invites if remote refused (PR #691)
* Fix bug where synapse attempted to backfill from itself (PR #693)
* Fix bug where profile information was not correctly added when joining remote
  rooms (PR #703)
* Fix bug where register API required incorrect key name for AS registration
  (PR #727)


Changes in synapse v0.14.0 (2016-03-30)
=======================================

No changes from v0.14.0-rc2

Changes in synapse v0.14.0-rc2 (2016-03-23)
===========================================

Features:

* Add published room list API (PR #657)

Changes:

* Change various caches to consume less memory (PR #656, #658, #660, #662,
  #663, #665)
* Allow rooms to be published without requiring an alias (PR #664)
* Intern common strings in caches to reduce memory footprint (#666)

Bug fixes:

* Fix reject invites over federation (PR #646)
* Fix bug where registration was not idempotent (PR #649)
* Update aliases event after deleting aliases (PR #652)
* Fix unread notification count, which was sometimes wrong (PR #661)

Changes in synapse v0.14.0-rc1 (2016-03-14)
===========================================

Features:

* Add event_id to response to state event PUT (PR #581)
* Allow guest users access to messages in rooms they have joined (PR #587)
* Add config for what state is included in a room invite (PR #598)
* Send the inviter's member event in room invite state (PR #607)
* Add error codes for malformed/bad JSON in /login (PR #608)
* Add support for changing the actions for default rules (PR #609)
* Add environment variable SYNAPSE_CACHE_FACTOR, default it to 0.1 (PR #612)
* Add ability for alias creators to delete aliases (PR #614)
* Add profile information to invites (PR #624)

Changes:

* Enforce user_id exclusivity for AS registrations (PR #572)
* Make adding push rules idempotent (PR #587)
* Improve presence performance (PR #582, #586)
* Change presence semantics for ``last_active_ago`` (PR #582, #586)
* Don't allow ``m.room.create`` to be changed (PR #596)
* Add 800x600 to default list of valid thumbnail sizes (PR #616)
* Always include kicks and bans in full /sync (PR #625)
* Send history visibility on boundary changes (PR #626)
* Register endpoint now returns a refresh_token (PR #637)

Bug fixes:

* Fix bug where we returned incorrect state in /sync (PR #573)
* Always return a JSON object from push rule API (PR #606)
* Fix bug where registering without a user id sometimes failed (PR #610)
* Report size of ExpiringCache in cache size metrics (PR #611)
* Fix rejection of invites to empty rooms (PR #615)
* Fix usage of ``bcrypt`` to not use ``checkpw`` (PR #619)
* Pin ``pysaml2`` dependency (PR #634)
* Fix bug in ``/sync`` where timeline order was incorrect for backfilled events
  (PR #635)

Changes in synapse v0.13.3 (2016-02-11)
=======================================

* Fix bug where ``/sync`` would occasionally return events in the wrong room.

Changes in synapse v0.13.2 (2016-02-11)
=======================================

* Fix bug where ``/events`` would fail to skip some events if there had been
  more events than the limit specified since the last request (PR #570)

Changes in synapse v0.13.1 (2016-02-10)
=======================================

* Bump matrix-angular-sdk (matrix web console) dependency to 0.6.8 to
  pull in the fix for SYWEB-361 so that the default client can display
  HTML messages again(!)

Changes in synapse v0.13.0 (2016-02-10)
=======================================

This version includes an upgrade of the schema, specifically adding an index to
the ``events`` table. This may cause synapse to pause for several minutes the
first time it is started after the upgrade.

Changes:

* Improve general performance (PR #540, #543. #544, #54, #549, #567)
* Change guest user ids to be incrementing integers (PR #550)
* Improve performance of public room list API (PR #552)
* Change profile API to omit keys rather than return null (PR #557)
* Add ``/media/r0`` endpoint prefix, which is equivalent to ``/media/v1/``
  (PR #595)

Bug fixes:

* Fix bug with upgrading guest accounts where it would fail if you opened the
  registration email on a different device (PR #547)
* Fix bug where unread count could be wrong (PR #568)



Changes in synapse v0.12.1-rc1 (2016-01-29)
===========================================

Features:

* Add unread notification counts in ``/sync`` (PR #456)
* Add support for inviting 3pids in ``/createRoom`` (PR #460)
* Add ability for guest accounts to upgrade (PR #462)
* Add ``/versions`` API (PR #468)
* Add ``event`` to ``/context`` API (PR #492)
* Add specific error code for invalid user names in ``/register`` (PR #499)
* Add support for push badge counts (PR #507)
* Add support for non-guest users to peek in rooms using ``/events`` (PR #510)

Changes:

* Change ``/sync`` so that guest users only get rooms they've joined (PR #469)
* Change to require unbanning before other membership changes (PR #501)
* Change default push rules to notify for all messages (PR #486)
* Change default push rules to not notify on membership changes (PR #514)
* Change default push rules in one to one rooms to only notify for events that
  are messages (PR #529)
* Change ``/sync`` to reject requests with a ``from`` query param (PR #512)
* Change server manhole to use SSH rather than telnet (PR #473)
* Change server to require AS users to be registered before use (PR #487)
* Change server not to start when ASes are invalidly configured (PR #494)
* Change server to require ID and ``as_token`` to be unique for AS's (PR #496)
* Change maximum pagination limit to 1000 (PR #497)

Bug fixes:

* Fix bug where ``/sync`` didn't return when something under the leave key
  changed (PR #461)
* Fix bug where we returned smaller rather than larger than requested
  thumbnails when ``method=crop`` (PR #464)
* Fix thumbnails API to only return cropped thumbnails when asking for a
  cropped thumbnail (PR #475)
* Fix bug where we occasionally still logged access tokens (PR #477)
* Fix bug where ``/events`` would always return immediately for guest users
  (PR #480)
* Fix bug where ``/sync`` unexpectedly returned old left rooms (PR #481)
* Fix enabling and disabling push rules (PR #498)
* Fix bug where ``/register`` returned 500 when given unicode username
  (PR #513)

Changes in synapse v0.12.0 (2016-01-04)
=======================================

* Expose ``/login`` under ``r0`` (PR #459)

Changes in synapse v0.12.0-rc3 (2015-12-23)
===========================================

* Allow guest accounts access to ``/sync`` (PR #455)
* Allow filters to include/exclude rooms at the room level
  rather than just from the components of the sync for each
  room. (PR #454)
* Include urls for room avatars in the response to ``/publicRooms`` (PR #453)
* Don't set a identicon as the avatar for a user when they register (PR #450)
* Add a ``display_name`` to third-party invites (PR #449)
* Send more information to the identity server for third-party invites so that
  it can send richer messages to the invitee (PR #446)
* Cache the responses to ``/initialSync`` for 5 minutes. If a client
  retries a request to ``/initialSync`` before the a response was computed
  to the first request then the same response is used for both requests
  (PR #457)
* Fix a bug where synapse would always request the signing keys of
  remote servers even when the key was cached locally (PR #452)
* Fix 500 when pagination search results (PR #447)
* Fix a bug where synapse was leaking raw email address in third-party invites
  (PR #448)

Changes in synapse v0.12.0-rc2 (2015-12-14)
===========================================

* Add caches for whether rooms have been forgotten by a user (PR #434)
* Remove instructions to use ``--process-dependency-link`` since all of the
  dependencies of synapse are on PyPI (PR #436)
* Parallelise the processing of ``/sync`` requests (PR #437)
* Fix race updating presence in ``/events`` (PR #444)
* Fix bug back-populating search results (PR #441)
* Fix bug calculating state in ``/sync`` requests (PR #442)

Changes in synapse v0.12.0-rc1 (2015-12-10)
===========================================

* Host the client APIs released as r0 by
  https://matrix.org/docs/spec/r0.0.0/client_server.html
  on paths prefixed by ``/_matrix/client/r0``. (PR #430, PR #415, PR #400)
* Updates the client APIs to match r0 of the matrix specification.

  * All APIs return events in the new event format, old APIs also include
    the fields needed to parse the event using the old format for
    compatibility. (PR #402)
  * Search results are now given as a JSON array rather than
    a JSON object (PR #405)
  * Miscellaneous changes to search (PR #403, PR #406, PR #412)
  * Filter JSON objects may now be passed as query parameters to ``/sync``
    (PR #431)
  * Fix implementation of ``/admin/whois`` (PR #418)
  * Only include the rooms that user has left in ``/sync`` if the client
    requests them in the filter (PR #423)
  * Don't push for ``m.room.message`` by default (PR #411)
  * Add API for setting per account user data (PR #392)
  * Allow users to forget rooms (PR #385)

* Performance improvements and monitoring:

  * Add per-request counters for CPU time spent on the main python thread.
    (PR #421, PR #420)
  * Add per-request counters for time spent in the database (PR #429)
  * Make state updates in the C+S API idempotent (PR #416)
  * Only fire ``user_joined_room`` if the user has actually joined. (PR #410)
  * Reuse a single http client, rather than creating new ones (PR #413)

* Fixed a bug upgrading from older versions of synapse on postgresql (PR #417)

Changes in synapse v0.11.1 (2015-11-20)
=======================================

* Add extra options to search API (PR #394)
* Fix bug where we did not correctly cap federation retry timers. This meant it
  could take several hours for servers to start talking to ressurected servers,
  even when they were receiving traffic from them (PR #393)
* Don't advertise login token flow unless CAS is enabled. This caused issues
  where some clients would always use the fallback API if they did not
  recognize all login flows (PR #391)
* Change /v2 sync API to rename ``private_user_data`` to ``account_data``
  (PR #386)
* Change /v2 sync API to remove the ``event_map`` and rename keys in ``rooms``
  object (PR #389)

Changes in synapse v0.11.0-r2 (2015-11-19)
==========================================

* Fix bug in database port script (PR #387)

Changes in synapse v0.11.0-r1 (2015-11-18)
==========================================

* Retry and fail federation requests more aggressively for requests that block
  client side requests (PR #384)

Changes in synapse v0.11.0 (2015-11-17)
=======================================

* Change CAS login API (PR #349)

Changes in synapse v0.11.0-rc2 (2015-11-13)
===========================================

* Various changes to /sync API response format (PR #373)
* Fix regression when setting display name in newly joined room over
  federation (PR #368)
* Fix problem where /search was slow when using SQLite (PR #366)

Changes in synapse v0.11.0-rc1 (2015-11-11)
===========================================

* Add Search API (PR #307, #324, #327, #336, #350, #359)
* Add 'archived' state to v2 /sync API (PR #316)
* Add ability to reject invites (PR #317)
* Add config option to disable password login (PR #322)
* Add the login fallback API (PR #330)
* Add room context API (PR #334)
* Add room tagging support (PR #335)
* Update v2 /sync API to match spec (PR #305, #316, #321, #332, #337, #341)
* Change retry schedule for application services (PR #320)
* Change retry schedule for remote servers (PR #340)
* Fix bug where we hosted static content in the incorrect place (PR #329)
* Fix bug where we didn't increment retry interval for remote servers (PR #343)

Changes in synapse v0.10.1-rc1 (2015-10-15)
===========================================

* Add support for CAS, thanks to Steven Hammerton (PR #295, #296)
* Add support for using macaroons for ``access_token`` (PR #256, #229)
* Add support for ``m.room.canonical_alias`` (PR #287)
* Add support for viewing the history of rooms that they have left. (PR #276,
  #294)
* Add support for refresh tokens (PR #240)
* Add flag on creation which disables federation of the room (PR #279)
* Add some room state to invites. (PR #275)
* Atomically persist events when joining a room over federation (PR #283)
* Change default history visibility for private rooms (PR #271)
* Allow users to redact their own sent events (PR #262)
* Use tox for tests (PR #247)
* Split up syutil into separate libraries (PR #243)

Changes in synapse v0.10.0-r2 (2015-09-16)
==========================================

* Fix bug where we always fetched remote server signing keys instead of using
  ones in our cache.
* Fix adding threepids to an existing account.
* Fix bug with invinting over federation where remote server was already in
  the room. (PR #281, SYN-392)

Changes in synapse v0.10.0-r1 (2015-09-08)
==========================================

* Fix bug with python packaging

Changes in synapse v0.10.0 (2015-09-03)
=======================================

No change from release candidate.

Changes in synapse v0.10.0-rc6 (2015-09-02)
===========================================

* Remove some of the old database upgrade scripts.
* Fix database port script to work with newly created sqlite databases.

Changes in synapse v0.10.0-rc5 (2015-08-27)
===========================================

* Fix bug that broke downloading files with ascii filenames across federation.

Changes in synapse v0.10.0-rc4 (2015-08-27)
===========================================

* Allow UTF-8 filenames for upload. (PR #259)

Changes in synapse v0.10.0-rc3 (2015-08-25)
===========================================

* Add ``--keys-directory`` config option to specify where files such as
  certs and signing keys should be stored in, when using ``--generate-config``
  or ``--generate-keys``. (PR #250)
* Allow ``--config-path`` to specify a directory, causing synapse to use all
  \*.yaml files in the directory as config files. (PR #249)
* Add ``web_client_location`` config option to specify static files to be
  hosted by synapse under ``/_matrix/client``. (PR #245)
* Add helper utility to synapse to read and parse the config files and extract
  the value of a given key. For example::

    $ python -m synapse.config read server_name -c homeserver.yaml
    localhost

  (PR #246)


Changes in synapse v0.10.0-rc2 (2015-08-24)
===========================================

* Fix bug where we incorrectly populated the ``event_forward_extremities``
  table, resulting in problems joining large remote rooms (e.g.
  ``#matrix:matrix.org``)
* Reduce the number of times we wake up pushers by not listening for presence
  or typing events, reducing the CPU cost of each pusher.


Changes in synapse v0.10.0-rc1 (2015-08-21)
===========================================

Also see v0.9.4-rc1 changelog, which has been amalgamated into this release.

General:

* Upgrade to Twisted 15 (PR #173)
* Add support for serving and fetching encryption keys over federation.
  (PR #208)
* Add support for logging in with email address (PR #234)
* Add support for new ``m.room.canonical_alias`` event. (PR #233)
* Change synapse to treat user IDs case insensitively during registration and
  login. (If two users already exist with case insensitive matching user ids,
  synapse will continue to require them to specify their user ids exactly.)
* Error if a user tries to register with an email already in use. (PR #211)
* Add extra and improve existing caches  (PR #212, #219, #226, #228)
* Batch various storage request (PR #226, #228)
* Fix bug where we didn't correctly log the entity that triggered the request
  if the request came in via an application service (PR #230)
* Fix bug where we needlessly regenerated the full list of rooms an AS is
  interested in. (PR #232)
* Add support for AS's to use v2_alpha registration API (PR #210)


Configuration:

* Add ``--generate-keys`` that will generate any missing cert and key files in
  the configuration files. This is equivalent to running ``--generate-config``
  on an existing configuration file. (PR #220)
* ``--generate-config`` now no longer requires a ``--server-name`` parameter
  when used on existing configuration files. (PR #220)
* Add ``--print-pidfile`` flag that controls the printing of the pid to stdout
  of the demonised process. (PR #213)

Media Repository:

* Fix bug where we picked a lower resolution image than requested. (PR #205)
* Add support for specifying if a the media repository should dynamically
  thumbnail images or not. (PR #206)

Metrics:

* Add statistics from the reactor to the metrics API. (PR #224, #225)

Demo Homeservers:

* Fix starting the demo homeservers without rate-limiting enabled. (PR #182)
* Fix enabling registration on demo homeservers (PR #223)


Changes in synapse v0.9.4-rc1 (2015-07-21)
==========================================

General:

* Add basic implementation of receipts. (SPEC-99)
* Add support for configuration presets in room creation API. (PR  #203)
* Add auth event that limits the visibility of history for new users.
  (SPEC-134)
* Add SAML2 login/registration support. (PR  #201. Thanks Muthu Subramanian!)
* Add client side key management APIs for end to end encryption. (PR #198)
* Change power level semantics so that you cannot kick, ban or change power
  levels of users that have equal or greater power level than you. (SYN-192)
* Improve performance by bulk inserting events where possible. (PR #193)
* Improve performance by bulk verifying signatures where possible. (PR #194)


Configuration:

* Add support for including TLS certificate chains.

Media Repository:

* Add Content-Disposition headers to content repository responses. (SYN-150)


Changes in synapse v0.9.3 (2015-07-01)
======================================

No changes from v0.9.3 Release Candidate 1.

Changes in synapse v0.9.3-rc1 (2015-06-23)
==========================================

General:

* Fix a memory leak in the notifier. (SYN-412)
* Improve performance of room initial sync. (SYN-418)
* General improvements to logging.
* Remove ``access_token`` query params from ``INFO`` level logging.

Configuration:

* Add support for specifying and configuring multiple listeners. (SYN-389)

Application services:

* Fix bug where synapse failed to send user queries to application services.

Changes in synapse v0.9.2-r2 (2015-06-15)
=========================================

Fix packaging so that schema delta python files get included in the package.

Changes in synapse v0.9.2 (2015-06-12)
======================================

General:

* Use ultrajson for json (de)serialisation when a canonical encoding is not
  required. Ultrajson is significantly faster than simplejson in certain
  circumstances.
* Use connection pools for outgoing HTTP connections.
* Process thumbnails on separate threads.

Configuration:

* Add option, ``gzip_responses``, to disable HTTP response compression.

Federation:

* Improve resilience of backfill by ensuring we fetch any missing auth events.
* Improve performance of backfill and joining remote rooms by removing
  unnecessary computations. This included handling events we'd previously
  handled as well as attempting to compute the current state for outliers.


Changes in synapse v0.9.1 (2015-05-26)
======================================

General:

* Add support for backfilling when a client paginates. This allows servers to
  request history for a room from remote servers when a client tries to
  paginate history the server does not have - SYN-36
* Fix bug where you couldn't disable non-default pushrules - SYN-378
* Fix ``register_new_user`` script - SYN-359
* Improve performance of fetching events from the database, this improves both
  initialSync and sending of events.
* Improve performance of event streams, allowing synapse to handle more
  simultaneous connected clients.

Federation:

* Fix bug with existing backfill implementation where it returned the wrong
  selection of events in some circumstances.
* Improve performance of joining remote rooms.

Configuration:

* Add support for changing the bind host of the metrics listener via the
  ``metrics_bind_host`` option.


Changes in synapse v0.9.0-r5 (2015-05-21)
=========================================

* Add more database caches to reduce amount of work done for each pusher. This
  radically reduces CPU usage when multiple pushers are set up in the same room.

Changes in synapse v0.9.0 (2015-05-07)
======================================

General:

* Add support for using a PostgreSQL database instead of SQLite. See
  `docs/postgres.rst`_ for details.
* Add password change and reset APIs. See `Registration`_ in the spec.
* Fix memory leak due to not releasing stale notifiers - SYN-339.
* Fix race in caches that occasionally caused some presence updates to be
  dropped - SYN-369.
* Check server name has not changed on restart.
* Add a sample systemd unit file and a logger configuration in
  contrib/systemd. Contributed Ivan Shapovalov.

Federation:

* Add key distribution mechanisms for fetching public keys of unavailable
  remote home servers. See `Retrieving Server Keys`_ in the spec.

Configuration:

* Add support for multiple config files.
* Add support for dictionaries in config files.
* Remove support for specifying config options on the command line, except
  for:

  * ``--daemonize`` - Daemonize the home server.
  * ``--manhole`` - Turn on the twisted telnet manhole service on the given
    port.
  * ``--database-path`` - The path to a sqlite database to use.
  * ``--verbose`` - The verbosity level.
  * ``--log-file`` - File to log to.
  * ``--log-config`` - Python logging config file.
  * ``--enable-registration`` - Enable registration for new users.

Application services:

* Reliably retry sending of events from Synapse to application services, as per
  `Application Services`_ spec.
* Application services can no longer register via the ``/register`` API,
  instead their configuration should be saved to a file and listed in the
  synapse ``app_service_config_files`` config option. The AS configuration file
  has the same format as the old ``/register`` request.
  See `docs/application_services.rst`_ for more information.

.. _`docs/postgres.rst`: docs/postgres.rst
.. _`docs/application_services.rst`: docs/application_services.rst
.. _`Registration`: https://github.com/matrix-org/matrix-doc/blob/master/specification/10_client_server_api.rst#registration
.. _`Retrieving Server Keys`: https://github.com/matrix-org/matrix-doc/blob/6f2698/specification/30_server_server_api.rst#retrieving-server-keys
.. _`Application Services`: https://github.com/matrix-org/matrix-doc/blob/0c6bd9/specification/25_application_service_api.rst#home-server---application-service-api

Changes in synapse v0.8.1 (2015-03-18)
======================================

* Disable registration by default. New users can be added using the command
  ``register_new_matrix_user`` or by enabling registration in the config.
* Add metrics to synapse. To enable metrics use config options
  ``enable_metrics`` and ``metrics_port``.
* Fix bug where banning only kicked the user.

Changes in synapse v0.8.0 (2015-03-06)
======================================

General:

* Add support for registration fallback. This is a page hosted on the server
  which allows a user to register for an account, regardless of what client
  they are using (e.g. mobile devices).

* Added new default push rules and made them configurable by clients:

  * Suppress all notice messages.
  * Notify when invited to a new room.
  * Notify for messages that don't match any rule.
  * Notify on incoming call.

Federation:

* Added per host server side rate-limiting of incoming federation requests.
* Added a ``/get_missing_events/`` API to federation to reduce number of
  ``/events/`` requests.

Configuration:

* Added configuration option to disable registration:
  ``disable_registration``.
* Added configuration option to change soft limit of number of open file
  descriptors: ``soft_file_limit``.
* Make ``tls_private_key_path`` optional when running with ``no_tls``.

Application services:

* Application services can now poll on the CS API ``/events`` for their events,
  by providing their application service ``access_token``.
* Added exclusive namespace support to application services API.


Changes in synapse v0.7.1 (2015-02-19)
======================================

* Initial alpha implementation of parts of the Application Services API.
  Including:

  - AS Registration / Unregistration
  - User Query API
  - Room Alias Query API
  - Push transport for receiving events.
  - User/Alias namespace admin control

* Add cache when fetching events from remote servers to stop repeatedly
  fetching events with bad signatures.
* Respect the per remote server retry scheme when fetching both events and
  server keys to reduce the number of times we send requests to dead servers.
* Inform remote servers when the local server fails to handle a received event.
* Turn off python bytecode generation due to problems experienced when
  upgrading from previous versions.

Changes in synapse v0.7.0 (2015-02-12)
======================================

* Add initial implementation of the query auth federation API, allowing
  servers to agree on whether an event should be allowed or rejected.
* Persist events we have rejected from federation, fixing the bug where
  servers would keep requesting the same events.
* Various federation performance improvements, including:

  - Add in memory caches on queries such as:

     * Computing the state of a room at a point in time, used for
       authorization on federation requests.
     * Fetching events from the database.
     * User's room membership, used for authorizing presence updates.

  - Upgraded JSON library to improve parsing and serialisation speeds.

* Add default avatars to new user accounts using pydenticon library.
* Correctly time out federation requests.
* Retry federation requests against different servers.
* Add support for push and push rules.
* Add alpha versions of proposed new CSv2 APIs, including ``/sync`` API.

Changes in synapse 0.6.1 (2015-01-07)
=====================================

* Major optimizations to improve performance of initial sync and event sending
  in large rooms (by up to 10x)
* Media repository now includes a Content-Length header on media downloads.
* Improve quality of thumbnails by changing resizing algorithm.

Changes in synapse 0.6.0 (2014-12-16)
=====================================

* Add new API for media upload and download that supports thumbnailing.
* Replicate media uploads over multiple homeservers so media is always served
  to clients from their local homeserver.  This obsoletes the
  --content-addr parameter and confusion over accessing content directly
  from remote homeservers.
* Implement exponential backoff when retrying federation requests when
  sending to remote homeservers which are offline.
* Implement typing notifications.
* Fix bugs where we sent events with invalid signatures due to bugs where
  we incorrectly persisted events.
* Improve performance of database queries involving retrieving events.

Changes in synapse 0.5.4a (2014-12-13)
======================================

* Fix bug while generating the error message when a file path specified in
  the config doesn't exist.

Changes in synapse 0.5.4 (2014-12-03)
=====================================

* Fix presence bug where some rooms did not display presence updates for
  remote users.
* Do not log SQL timing log lines when started with "-v"
* Fix potential memory leak.

Changes in synapse 0.5.3c (2014-12-02)
======================================

* Change the default value for the `content_addr` option to use the HTTP
  listener, as by default the HTTPS listener will be using a self-signed
  certificate.

Changes in synapse 0.5.3 (2014-11-27)
=====================================

* Fix bug that caused joining a remote room to fail if a single event was not
  signed correctly.
* Fix bug which caused servers to continuously try and fetch events from other
  servers.

Changes in synapse 0.5.2 (2014-11-26)
=====================================

Fix major bug that caused rooms to disappear from peoples initial sync.

Changes in synapse 0.5.1 (2014-11-26)
=====================================
See UPGRADES.rst for specific instructions on how to upgrade.

 * Fix bug where we served up an Event that did not match its signatures.
 * Fix regression where we no longer correctly handled the case where a
   homeserver receives an event for a room it doesn't recognise (but is in.)

Changes in synapse 0.5.0 (2014-11-19)
=====================================
This release includes changes to the federation protocol and client-server API
that is not backwards compatible.

This release also changes the internal database schemas and so requires servers to
drop their current history. See UPGRADES.rst for details.

Homeserver:
 * Add authentication and authorization to the federation protocol. Events are
   now signed by their originating homeservers.
 * Implement the new authorization model for rooms.
 * Split out web client into a seperate repository: matrix-angular-sdk.
 * Change the structure of PDUs.
 * Fix bug where user could not join rooms via an alias containing 4-byte
   UTF-8 characters.
 * Merge concept of PDUs and Events internally.
 * Improve logging by adding request ids to log lines.
 * Implement a very basic room initial sync API.
 * Implement the new invite/join federation APIs.

Webclient:
 * The webclient has been moved to a seperate repository.

Changes in synapse 0.4.2 (2014-10-31)
=====================================

Homeserver:
 * Fix bugs where we did not notify users of correct presence updates.
 * Fix bug where we did not handle sub second event stream timeouts.

Webclient:
 * Add ability to click on messages to see JSON.
 * Add ability to redact messages.
 * Add ability to view and edit all room state JSON.
 * Handle incoming redactions.
 * Improve feedback on errors.
 * Fix bugs in mobile CSS.
 * Fix bugs with desktop notifications.

Changes in synapse 0.4.1 (2014-10-17)
=====================================
Webclient:
 * Fix bug with display of timestamps.

Changes in synpase 0.4.0 (2014-10-17)
=====================================
This release includes changes to the federation protocol and client-server API
that is not backwards compatible.

The Matrix specification has been moved to a separate git repository:
http://github.com/matrix-org/matrix-doc

You will also need an updated syutil and config. See UPGRADES.rst.

Homeserver:
 * Sign federation transactions to assert strong identity over federation.
 * Rename timestamp keys in PDUs and events from 'ts' and 'hsob_ts' to 'origin_server_ts'.


Changes in synapse 0.3.4 (2014-09-25)
=====================================
This version adds support for using a TURN server. See docs/turn-howto.rst on
how to set one up.

Homeserver:
 * Add support for redaction of messages.
 * Fix bug where inviting a user on a remote home server could take up to
   20-30s.
 * Implement a get current room state API.
 * Add support specifying and retrieving turn server configuration.

Webclient:
 * Add button to send messages to users from the home page.
 * Add support for using TURN for VoIP calls.
 * Show display name change messages.
 * Fix bug where the client didn't get the state of a newly joined room
   until after it has been refreshed.
 * Fix bugs with tab complete.
 * Fix bug where holding down the down arrow caused chrome to chew 100% CPU.
 * Fix bug where desktop notifications occasionally used "Undefined" as the
   display name.
 * Fix more places where we sometimes saw room IDs incorrectly.
 * Fix bug which caused lag when entering text in the text box.

Changes in synapse 0.3.3 (2014-09-22)
=====================================

Homeserver:
 * Fix bug where you continued to get events for rooms you had left.

Webclient:
 * Add support for video calls with basic UI.
 * Fix bug where one to one chats were named after your display name rather
   than the other person's.
 * Fix bug which caused lag when typing in the textarea.
 * Refuse to run on browsers we know won't work.
 * Trigger pagination when joining new rooms.
 * Fix bug where we sometimes didn't display invitations in recents.
 * Automatically join room when accepting a VoIP call.
 * Disable outgoing and reject incoming calls on browsers we don't support
   VoIP in.
 * Don't display desktop notifications for messages in the room you are
   non-idle and speaking in.

Changes in synapse 0.3.2 (2014-09-18)
=====================================

Webclient:
 * Fix bug where an empty "bing words" list in old accounts didn't send
   notifications when it should have done.

Changes in synapse 0.3.1 (2014-09-18)
=====================================
This is a release to hotfix v0.3.0 to fix two regressions.

Webclient:
 * Fix a regression where we sometimes displayed duplicate events.
 * Fix a regression where we didn't immediately remove rooms you were
   banned in from the recents list.

Changes in synapse 0.3.0 (2014-09-18)
=====================================
See UPGRADE for information about changes to the client server API, including
breaking backwards compatibility with VoIP calls and registration API.

Homeserver:
 * When a user changes their displayname or avatar the server will now update
   all their join states to reflect this.
 * The server now adds "age" key to events to indicate how old they are. This
   is clock independent, so at no point does any server or webclient have to
   assume their clock is in sync with everyone else.
 * Fix bug where we didn't correctly pull in missing PDUs.
 * Fix bug where prev_content key wasn't always returned.
 * Add support for password resets.

Webclient:
 * Improve page content loading.
 * Join/parts now trigger desktop notifications.
 * Always show room aliases in the UI if one is present.
 * No longer show user-count in the recents side panel.
 * Add up & down arrow support to the text box for message sending to step
   through your sent history.
 * Don't display notifications for our own messages.
 * Emotes are now formatted correctly in desktop notifications.
 * The recents list now differentiates between public & private rooms.
 * Fix bug where when switching between rooms the pagination flickered before
   the view jumped to the bottom of the screen.
 * Add bing word support.

Registration API:
 * The registration API has been overhauled to function like the login API. In
   practice, this means registration requests must now include the following:
   'type':'m.login.password'. See UPGRADE for more information on this.
 * The 'user_id' key has been renamed to 'user' to better match the login API.
 * There is an additional login type: 'm.login.email.identity'.
 * The command client and web client have been updated to reflect these changes.

Changes in synapse 0.2.3 (2014-09-12)
=====================================

Homeserver:
 * Fix bug where we stopped sending events to remote home servers if a
   user from that home server left, even if there were some still in the
   room.
 * Fix bugs in the state conflict resolution where it was incorrectly
   rejecting events.

Webclient:
 * Display room names and topics.
 * Allow setting/editing of room names and topics.
 * Display information about rooms on the main page.
 * Handle ban and kick events in real time.
 * VoIP UI and reliability improvements.
 * Add glare support for VoIP.
 * Improvements to initial startup speed.
 * Don't display duplicate join events.
 * Local echo of messages.
 * Differentiate sending and sent of local echo.
 * Various minor bug fixes.

Changes in synapse 0.2.2 (2014-09-06)
=====================================

Homeserver:
 * When the server returns state events it now also includes the previous
   content.
 * Add support for inviting people when creating a new room.
 * Make the homeserver inform the room via `m.room.aliases` when a new alias
   is added for a room.
 * Validate `m.room.power_level` events.

Webclient:
 * Add support for captchas on registration.
 * Handle `m.room.aliases` events.
 * Asynchronously send messages and show a local echo.
 * Inform the UI when a message failed to send.
 * Only autoscroll on receiving a new message if the user was already at the
   bottom of the screen.
 * Add support for ban/kick reasons.

Changes in synapse 0.2.1 (2014-09-03)
=====================================

Homeserver:
 * Added support for signing up with a third party id.
 * Add synctl scripts.
 * Added rate limiting.
 * Add option to change the external address the content repo uses.
 * Presence bug fixes.

Webclient:
 * Added support for signing up with a third party id.
 * Added support for banning and kicking users.
 * Added support for displaying and setting ops.
 * Added support for room names.
 * Fix bugs with room membership event display.

Changes in synapse 0.2.0 (2014-09-02)
=====================================
This update changes many configuration options, updates the
database schema and mandates SSL for server-server connections.

Homeserver:
 * Require SSL for server-server connections.
 * Add SSL listener for client-server connections.
 * Add ability to use config files.
 * Add support for kicking/banning and power levels.
 * Allow setting of room names and topics on creation.
 * Change presence to include last seen time of the user.
 * Change url path prefix to /_matrix/...
 * Bug fixes to presence.

Webclient:
 * Reskin the CSS for registration and login.
 * Various improvements to rooms CSS.
 * Support changes in client-server API.
 * Bug fixes to VOIP UI.
 * Various bug fixes to handling of changes to room member list.

Changes in synapse 0.1.2 (2014-08-29)
=====================================

Webclient:
 * Add basic call state UI for VoIP calls.

Changes in synapse 0.1.1 (2014-08-29)
=====================================

Homeserver:
    * Fix bug that caused the event stream to not notify some clients about
      changes.

Changes in synapse 0.1.0 (2014-08-29)
=====================================
Presence has been reenabled in this release.

Homeserver:
 * Update client to server API, including:
    - Use a more consistent url scheme.
    - Provide more useful information in the initial sync api.
 * Change the presence handling to be much more efficient.
 * Change the presence server to server API to not require explicit polling of
   all users who share a room with a user.
 * Fix races in the event streaming logic.

Webclient:
 * Update to use new client to server API.
 * Add basic VOIP support.
 * Add idle timers that change your status to away.
 * Add recent rooms column when viewing a room.
 * Various network efficiency improvements.
 * Add basic mobile browser support.
 * Add a settings page.

Changes in synapse 0.0.1 (2014-08-22)
=====================================
Presence has been disabled in this release due to a bug that caused the
homeserver to spam other remote homeservers.

Homeserver:
 * Completely change the database schema to support generic event types.
 * Improve presence reliability.
 * Improve reliability of joining remote rooms.
 * Fix bug where room join events were duplicated.
 * Improve initial sync API to return more information to the client.
 * Stop generating fake messages for room membership events.

Webclient:
 * Add tab completion of names.
 * Add ability to upload and send images.
 * Add profile pages.
 * Improve CSS layout of room.
 * Disambiguate identical display names.
 * Don't get remote users display names and avatars individually.
 * Use the new initial sync API to reduce number of round trips to the homeserver.
 * Change url scheme to use room aliases instead of room ids where known.
 * Increase longpoll timeout.

Changes in synapse 0.0.0 (2014-08-13)
=====================================

 * Initial alpha release
