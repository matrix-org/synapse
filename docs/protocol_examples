PUT /send/abc/ HTTP/1.1
Host: ...
Content-Length: ...
Content-Type: application/json

{
    "origin": "localhost:5000",
    "pdus": [
        {
            "content": {},
            "context": "tng",
            "depth": 12,
            "is_state": false,
            "origin": "localhost:5000",
            "pdu_id": 1404381396854,
            "pdu_type": "feedback",
            "prev_pdus": [
                [
                    "1404381395883",
                    "localhost:6000"
                ]
            ],
            "ts": 1404381427581
        }
    ],
    "prev_ids": [
        "1404381396852"
    ],
    "ts": 1404381427823
}

HTTP/1.1 200 OK
...

======================================

GET /pull/-1/ HTTP/1.1
Host: ...
Content-Length: 0

HTTP/1.1 200 OK
Content-Length: ...
Content-Type: application/json

{
    origin: ...,
    prev_ids: ...,
    data: [
        {
            data_id: ...,
            prev_pdus: [...],
            depth: ...,
            ts: ...,
            context: ...,
            origin: ...,
            content: {
                ...
            }
        },
        ...,
    ]
}


