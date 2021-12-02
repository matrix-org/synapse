## Admin FAQ

How do I become a server admin?
---
If your server already has an admin account you should use the user admin API to promote other accounts to become admins. See [User Admin API](../../admin_api/user_admin_api.md#Change-whether-a-user-is-a-server-administrator-or-not)

If you don't have any admin accounts yet you won't be able to use the admin API so you'll have to edit the database manually. Manually editing the database is generally not recommended so once you have an admin account, use the admin APIs to make further changes.

```sql
UPDATE users SET admin = 1 WHERE name = '@foo:bar.com';
```
What servers are my server talking to?
---
Run this sql query on your db:
```sql
SELECT * FROM destinations;
```

What servers are currently participating in this room?
---
Run this sql query on your db:
```sql
SELECT DISTINCT split_part(state_key, ':', 2)
    FROM current_state_events AS c
    INNER JOIN room_memberships AS m USING (room_id, event_id)
    WHERE room_id = '!cURbafjkfsMDVwdRDQ:matrix.org' AND membership = 'join';
```

What users are registered on my server?
---
```sql
SELECT NAME from users;
```

Manually resetting passwords:
---
See https://github.com/matrix-org/synapse/blob/master/README.rst#password-reset

I have a problem with my server. Can I just delete my database and start again?
---
Deleting your database is unlikely to make anything better. 

It's easy to make the mistake of thinking that you can start again from a clean slate by dropping your database, but things don't work like that in a federated network: lots of other servers have information about your server.

For example: other servers might think that you are in a room, your server will think that you are not, and you'll probably be unable to interact with that room in a sensible way ever again.

In general, there are better solutions to any problem than dropping the database. Come and seek help in https://matrix.to/#/#synapse:matrix.org.

There are two exceptions when it might be sensible to delete your database and start again:
* You have *never* joined any rooms which are federated with other servers. For instance, a local deployment which the outside world can't talk to. 
* You are changing the `server_name` in the homeserver configuration. In effect this makes your server a completely new one from the point of view of the network, so in this case it makes sense to start with a clean database.
(In both cases you probably also want to clear out the media_store.)

I've stuffed up access to my room, how can I delete it to free up the alias?
---
Using the following curl command:
```
curl -H 'Authorization: Bearer <access-token>' -X DELETE https://matrix.org/_matrix/client/r0/directory/room/<room-alias>
```
`<access-token>` - can be obtained in riot by looking in the riot settings, down the bottom is:
Access Token:\<click to reveal\> 

`<room-alias>` - the room alias, eg. #my_room:matrix.org this possibly needs to be URL encoded also, for example  %23my_room%3Amatrix.org

How can I find the lines corresponding to a given HTTP request in my homeserver log?
---

Synapse tags each log line according to the HTTP request it is processing. When it finishes processing each request, it logs a line containing the words `Processed request: `. For example:

```
2019-02-14 22:35:08,196 - synapse.access.http.8008 - 302 - INFO - GET-37 - ::1 - 8008 - {@richvdh:localhost} Processed request: 0.173sec/0.001sec (0.002sec, 0.000sec) (0.027sec/0.026sec/2) 687B 200 "GET /_matrix/client/r0/sync HTTP/1.1" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36" [0 dbevts]"
```

Here we can see that the request has been tagged with `GET-37`. (The tag depends on the method of the HTTP request, so might start with `GET-`, `PUT-`, `POST-`, `OPTIONS-` or `DELETE-`.) So to find all lines corresponding to this request, we can do:

```
grep 'GET-37' homeserver.log
```

If you want to paste that output into a github issue or matrix room, please remember to surround it with triple-backticks (```) to make it legible (see https://help.github.com/en/articles/basic-writing-and-formatting-syntax#quoting-code).


What do all those fields in the 'Processed' line mean?
---
See [Request log format](request_log.md).


What are the biggest rooms on my server?
---

```sql
SELECT s.canonical_alias, g.room_id, count(*) AS num_rows 
FROM 
  state_groups_state AS g, 
  room_stats_state AS s 
WHERE g.room_id = s.room_id 
GROUP BY s.canonical_alias, g.room_id
ORDER BY num_rows desc 
LIMIT 10;
```

You can also use the [List Room API](../../admin_api/rooms.md#list-room-api)
and `order_by` `state_events`.
