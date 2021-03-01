# Request log format

HTTP request logs are written by synapse (see [`site.py`](../synapse/http/site.py) for details).

See the following for how to decode the dense data available here.

```
2020-10-01 12:00:00,000 - synapse.access.http.8008 - 311 - INFO - PUT-1000- 192.168.0.1 - 8008 - {another-matrix-server.com} Processed request: 0.100sec/-0.000sec (0.000sec, 0.000sec) (0.001sec/0.090sec/3) 11B 200 "PUT /_matrix/federation/v1/send/1600000000000 HTTP/1.1" "Synapse/1.20.1" [0 dbevts]
-AAAAAAAAAAAAAAAAAAAAA-   -BBBBBBBBBBBBBBBBBBBBBB-   -C-   -DD-   -EEEEEE-  -FFFFFFFFF-   -GG-    -HHHHHHHHHHHHHHHHHHHHHHH-                     -IIIIII- -JJJJJJJ-  -KKKKKK-, -LLLLLL-  -MMMMMMM- -NNNNNN- O  -P- -Q-  -RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR-   -SSSSSSSSSSSS-   -TTTTTT-
```


| Part  | Explaination | 
| ----- | ------------ |
| AAAA  | Timestamp request was logged (not recieved) |
| BBBB  | Logger name (usually the same as the python class ) |
| CCCC  | Line number in code |
| DDDD  | Log Level |
| EEEE  | Request Identifier (This identifier is shared by related log lines)|
| FFFF  | Source IP (Or X-Forwarded-For if enabled) |
| GGGG  | Server Port |
| HHHH  | Federated Server or Local User making request (blank if unauthenticated or not supplied) |
| IIII  | Total Time to process |
| JJJJ  | Time to send response over network once generated |
| KKKK  | Userland CPU time |
| LLLL  | System CPU time |
| MMMM  | Total time waiting for a free DB connection from the pool |
| NNNN  | Total time waiting for response to DB queries |
| OOOO  | Count of DB transactions performed |
| PPPP  | Response body size |
| QQQQ  | Response status code |
| RRRR  | Request |
| SSSS  | User-agent |
| TTTT  | Events fetched from DB to service this request (note that this does not include events fetched from the cache) |
