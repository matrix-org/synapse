# Using a forward proxy with Synapse

You can use Synapse with a forward or outbound proxy. This will be neccssary
for expamle in corporate environments behind a DMZ (demilitarized zone).
Synapse supports routing outbound HTTP(S) requests via a proxy. Only HTTP(S)
proxy is supported, not SOCKS proxy or anything else.

## Configure

The `http_proxy`, `https_proxy`, `no_proxy` environment variable is used to
specify proxy settings. The environment variable is not case sensitive.
- `http_proxy`: Proxy server to use for HTTP requests.
- `https_proxy`: Proxy server to use for HTTPS requests.
- `no_proxy`: Comma-separated list of hosts, IP addresses, or IP ranges in CIDR
  format which do not use a proxy and Synapse use a direct connection.

The proxy setting has the form: `[scheme://][<username>:<password>@]<host>[:<port>]`
- Supported scheme is `http://` and `https://`. Default scheme is `http://`.
  It is recommended to set a scheme. The default value is for compatibility
  reasons. If scheme is set to `https://` the connection uses TLS between
  Synapse and proxy.

  **NOTE**: Synapse validates the certificates. If the certificate is not
  valid, then the connection is dropped.
- Default port if not given is `1080`.
- Username and password is optional and will be used for authenticate against
  proxy.

**Examples**
- HTTP_PROXY=http://USERNAME:PASSWORD@10.0.1.1:8080/
- HTTPS_PROXY=http://USERNAME:PASSWORD@proxy.example.com:8080/
- NO_PROXY=master.hostname.example.com,10.1.0.0/16,172.30.0.0/16

**NOTE**:
Blacklisting IP addresses does not work for connections throug a proxy because
the proxy server resolves DNS names and not Synapse. In this case you have to
use your firewall or proxy for blacklisting IP addresses.

## Connection types

The proxy will be **used** for:

- push
- url previews
- phone-home stats
- recaptcha validation
- CAS auth validation

It will **not be used** for:

- Application Services
- Identity servers
- Outbound federation
- In worker configurations
  - connections from workers to masters
  - connections from workers to redis

## Troubleshooting

If a proxy server is used with TLS (HTTPS) and no connections are established,
it is most likely due to the proxy's certificates. To test this, the validation
in Synapse can be deactivated.

**NOTE**: This has an impact on security and is for testing purposes only!

To deactivate the certificate validation, the following setting must be made in
[homserver.yaml](../usage/configuration/homeserver_sample_config.md).

```yaml
use_insecure_ssl_client_just_for_testing_do_not_use: true
```
