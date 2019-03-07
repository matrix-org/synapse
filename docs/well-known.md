# Well-Known

The mapping for a server name to a hostname for federation is done via
`SRV` records. Synapse v1.0 mandates valid X.509 certificates for the
federation endpoint where the certificate must match the server name.

This presents difficulties for hosted server offerings: ExampleCorp
may want to delegate responsibility for running its Matrix homeserver to an
outside supplier, but it may be difficult for that supplier to obtain a TLS
certificate for `example.com` (and ExampleCorp may be reluctant to let them have
one).

`.well-known` solves this problem by augmenting the current `SRV` record
with a `.well-known` lookup.

## Configuring `.well-known`

 1. Give synapse a certificate corresponding to the target domain
    (`customer.example.com`). Currently Synapse's ACME
    support [does not support
    this](https://github.com/matrix-org/synapse/issues/4552), so you will have
    to acquire a certificate yourself and give it to Synapse via
    `tls_certificate_path` and `tls_private_key_path`.

 2. Restart Synapse to ensure the new certificate is loaded.

 3. Arrange for a `.well-known` file at
    `https://<server_name>/.well-known/matrix/server` with contents:

    ```json
    {"m.server": "<target server name>"}
    ```

    where the target server name is resolved as usual (i.e. SRV lookup, falling
    back to talking to port 8448).

    In the above `example.com` exmaple above, where synapse is listening on
    port 8000, `https://example.com/.well-known/matrix/server` should have
    `m.server` set to one of:

    1. `customer.example.com` ─ with a SRV record on
       `_matrix._tcp.customer.example.com` pointing to port 8000, or:

    2. `customer.example.com` ─ updating synapse to listen on the default port
       8448, or:

    3. `customer.example.com:8000` ─ ensuring that if there is a reverse proxy
       on `customer.example.com:8000` it correctly handles HTTP requests with
       Host header set to `customer.example.com:8000`.
