# Request log format

HTTP request logs are written by synapse (see [`synapse/http/site.py`](https://github.com/matrix-org/synapse/tree/develop/synapse/http/site.py) for details).

See the following for how to decode the dense data available from the default logging configuration.

```
2020-10-01 12:00:00,000 - synapse.access.http.8008 - 311 - INFO - PUT-1000- 192.168.0.1 - 8008 - {another-matrix-server.com} Processed request: 0.100sec/-0.000sec (0.000sec, 0.000sec) (0.001sec/0.090sec/3) 11B !200 "PUT /_matrix/federation/v1/send/1600000000000 HTTP/1.1" "Synapse/1.20.1" [0 dbevts]
-AAAAAAAAAAAAAAAAAAAAA-   -BBBBBBBBBBBBBBBBBBBBBB-   -C-   -DD-   -EEEEEE-  -FFFFFFFFF-   -GG-    -HHHHHHHHHHHHHHHHHHHHHHH-                     -IIIIII- -JJJJJJJ-  -KKKKKK-, -LLLLLL-  -MMMMMMM- -NNNNNN- O  -P- -QQ-  -RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR-   -SSSSSSSSSSSS-   -TTTTTT-
```


| Part  | Explanation |
| ----- | ------------ |
| AAAA  | Timestamp request was logged (not received) |
| BBBB  | Logger name (`synapse.access.(http\|https).<tag>`, where 'tag' is defined in the [`listeners`](../configuration/config_documentation.md#listeners) config section, normally the port) |
| CCCC  | Line number in code |
| DDDD  | Log Level |
| EEEE  | Request Identifier (This identifier is shared by related log lines)|
| FFFF  | Source IP (Or X-Forwarded-For if enabled) |
| GGGG  | Server Port |
| HHHH  | Federated Server or Local User making request (blank if unauthenticated or not supplied).<br/>If this is of the form `@aaa:example.com|@bbb:example.com`, then that means that `@aaa:example.com` is authenticated but they are controlling `@bbb:example.com`, e.g. if `aaa` is controlling `bbb` [via the admin API](https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#login-as-a-user). |
| IIII  | Total Time to process the request |
| JJJJ  | Time to send response over network once generated (this may be negative if the socket is closed before the response is generated)|
| KKKK  | Userland CPU time |
| LLLL  | System CPU time |
| MMMM  | Total time waiting for a free DB connection from the pool across all parallel DB work from this request |
| NNNN  | Total time waiting for response to DB queries across all parallel DB work from this request |
| OOOO  | Count of DB transactions performed |
| PPPP  | Response body size |
| QQQQ  | Response status code<br/>Suffixed with `!` if the socket was closed before the response was generated.<br/>A `499!` status code indicates that Synapse also cancelled request processing after the socket was closed.<br/> |
| RRRR  | Request |
| SSSS  | User-agent |
| TTTT  | Events fetched from DB to service this request (note that this does not include events fetched from the cache) |


MMMM / NNNN can be greater than IIII if there are multiple slow database queries
running in parallel.

Some actions can result in multiple identical http requests, which will return
the same data, but only the first request will report time/transactions in
`KKKK`/`LLLL`/`MMMM`/`NNNN`/`OOOO` - the others will be awaiting the first query to return a
response and will simultaneously return with the first request, but with very
small processing times.
