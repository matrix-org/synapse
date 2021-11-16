## Some useful SQL queries for Synapse Admins

## Size of full matrix db
`SELECT pg_size_pretty( pg_database_size( 'matrix' ) );`
### Result example:
``` 
pg_size_pretty 
----------------
 6420 MB
(1 row)
```
## Show top 20 larger rooms by state events count
```sql
SELECT r.name, s.room_id, s.current_state_events
  FROM room_stats_current s
  LEFT JOIN room_stats_state r USING (room_id)
  ORDER BY current_state_events DESC
  LIMIT 20;
```

and by state_group_events count:
```sql
SELECT rss.name, s.room_id, count(s.room_id) FROM state_groups_state s
LEFT JOIN room_stats_state rss USING (room_id)
GROUP BY s.room_id, rss.name        
ORDER BY count(s.room_id) DESC
LIMIT 20;
```
plus same, but with join removed for performance reasons:
```sql
SELECT s.room_id, count(s.room_id) FROM state_groups_state s
GROUP BY s.room_id        
ORDER BY count(s.room_id) DESC
LIMIT 20;
```

## Show top 20 larger tables by row count
```sql
SELECT relname, n_live_tup as rows
  FROM pg_stat_user_tables 
  ORDER BY n_live_tup DESC
  LIMIT 20;
```
This query is quick, but may be very approximate, for exact number of rows use `SELECT COUNT(*) FROM <table_name>`.
### Result example:
```
state_groups_state - 161687170
event_auth - 8584785
event_edges - 6995633
event_json - 6585916
event_reference_hashes - 6580990
events - 6578879
received_transactions - 5713989
event_to_state_groups - 4873377
stream_ordering_to_exterm - 4136285
current_state_delta_stream - 3770972
event_search - 3670521
state_events - 2845082
room_memberships - 2785854
cache_invalidation_stream - 2448218
state_groups - 1255467
state_group_edges - 1229849
current_state_events - 1222905
users_in_public_rooms - 364059
device_lists_stream - 326903
user_directory_search - 316433
```

## Show top 20 rooms by new events count in last 1 day:
```sql
SELECT e.room_id, r.name, COUNT(e.event_id) cnt FROM events e
LEFT JOIN room_stats_state r USING (room_id)
WHERE e.origin_server_ts >= DATE_PART('epoch', NOW() - INTERVAL '1 day') * 1000 GROUP BY e.room_id, r.name ORDER BY cnt DESC LIMIT 20;
```

## Show top 20 users on homeserver by sent events (messages) at last month:
```sql
SELECT user_id, SUM(total_events) 
   FROM user_stats_historical
   WHERE TO_TIMESTAMP(end_ts/1000) AT TIME ZONE 'UTC' > date_trunc('day', now() - interval '1 month')
   GROUP BY user_id
   ORDER BY SUM(total_events) DESC 
   LIMIT 20;
```

## Show last 100 messages from needed user, with room names:
```sql
SELECT e.room_id, r.name, e.event_id, e.type, e.content, j.json FROM events e
  LEFT JOIN event_json j USING (room_id)
  LEFT JOIN room_stats_state r USING (room_id)
  WHERE sender = '@LOGIN:example.com'
  AND e.type = 'm.room.message'
  ORDER BY stream_ordering DESC
  LIMIT 100;
```

## Show top 20 larger tables by storage size
```sql
SELECT nspname || '.' || relname AS "relation",
    pg_size_pretty(pg_total_relation_size(C.oid)) AS "total_size"
  FROM pg_class C
  LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
  WHERE nspname NOT IN ('pg_catalog', 'information_schema')
    AND C.relkind <> 'i'
    AND nspname !~ '^pg_toast'
  ORDER BY pg_total_relation_size(C.oid) DESC
  LIMIT 20;
```
### Result example:
```
public.state_groups_state - 27 GB
public.event_json - 9855 MB
public.events - 3675 MB
public.event_edges - 3404 MB
public.received_transactions - 2745 MB
public.event_reference_hashes - 1864 MB
public.event_auth - 1775 MB
public.stream_ordering_to_exterm - 1663 MB
public.event_search - 1370 MB
public.room_memberships - 1050 MB
public.event_to_state_groups - 948 MB
public.current_state_delta_stream - 711 MB
public.state_events - 611 MB
public.presence_stream - 530 MB
public.current_state_events - 525 MB
public.cache_invalidation_stream - 466 MB
public.receipts_linearized - 279 MB
public.state_groups - 160 MB
public.device_lists_remote_cache - 124 MB
public.state_group_edges - 122 MB
```

## Show rooms with names, sorted by events in this rooms
`echo "select event_json.room_id,room_stats_state.name from event_json,room_stats_state where room_stats_state.room_id=event_json.room_id" | psql synapse | sort | uniq -c | sort -n`
### Result example:
```
   9459  !FPUfgzXYWTKgIrwKxW:matrix.org              | This Week in Matrix
   9459  !FPUfgzXYWTKgIrwKxW:matrix.org              | This Week in Matrix (TWIM)
  17799  !iDIOImbmXxwNngznsa:matrix.org              | Linux in Russian
  18739  !GnEEPYXUhoaHbkFBNX:matrix.org              | Riot Android
  23373  !QtykxKocfZaZOUrTwp:matrix.org              | Matrix HQ
  39504  !gTQfWzbYncrtNrvEkB:matrix.org              | ru.[matrix]
  43601  !iNmaIQExDMeqdITdHH:matrix.org              | Riot
  43601  !iNmaIQExDMeqdITdHH:matrix.org              | Riot Web/Desktop
```

## Lookup room state info by list of room_id
```sql
SELECT rss.room_id, rss.name, rss.canonical_alias, rss.topic, rss.encryption, rsc.joined_members, rsc.local_users_in_room, rss.join_rules
FROM room_stats_state rss
LEFT JOIN room_stats_current rsc USING (room_id)
WHERE room_id IN (WHERE room_id IN (
 '!OGEhHVWSdvArJzumhm:matrix.org',
 '!YTvKGNlinIzlkMTVRl:matrix.org'
)
```