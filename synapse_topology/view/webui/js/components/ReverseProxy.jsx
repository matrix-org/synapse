import React, { useState } from 'react';

import ContentWrapper from './ContentWrapper';

import {
  REVERSE_PROXY_TYPES
} from '../actions/constants'

const apacheLink = "http://httpd.apache.org/";
const caddyLink = "https://caddyserver.com/";
const haproxyLink = "http://www.haproxy.org/";
const nginxLink = "https://www.nginx.com/";
const proxyInfoLink = "https://github.com/matrix-org/synapse/blob/master/docs/reverse_proxy.rst";

export default ({ onClick }) => {
  const [reverseProxy, setReverseProxy] = useState(REVERSE_PROXY_TYPES.NONE);

  const onChange = event => {
    setReverseProxy(event.target.value);
  }

  return <ContentWrapper>
    <h1>Reverse Proxy</h1>
    <p>
      It is recommended to use Synapse behind a reverse proxy such as <a target="_blank" href={apacheLink}>Apache</a>, <a target="_blank" href={caddyLink}>Caddy</a>, <a target="_blank" href={haproxyLink}>HAProxy</a>, or <a target="_blank" href={nginxLink}>NGiNX</a>.
    </p>
    <p>
      The main benefit to this is that the reverse proxy can listen on the privilaged port
      443 (which clients like riot expect to connect to) on behalf of synapse. The incoming traffic
      is then forwarded to Synapse on a non privilaged port.
      <br />
      You need root to listen on ports 0 to 1024 inclusive and
      running synapse with root privileges is <b>strongly discouraged</b>.
      Reverse proxies are more secure, run with root and pass things on like nobody's business.
      <br />
      (Note: you can also have synapse use a non privilaged port
      by using one of the delegation methods mentioned earlier.)
    </p>
    <p>
      If you chose to use a Reverse Proxy (good for you) we'll provide you with
      configuration templates later. Easy breasy.
    </p>
    <p>
      More information <a target="_blank" href={proxyInfoLink}> in the docs.</a>
    </p>
    <select defaultValue={REVERSE_PROXY_TYPES.NGINX} onChange={(e) => setReverseProxy(e.target.value)}>
      <option value={REVERSE_PROXY_TYPES.APACHE}>Apache</option>
      <option value={REVERSE_PROXY_TYPES.CADDY}>Caddy</option>
      <option value={REVERSE_PROXY_TYPES.HAPROXY}>HAProxy</option>
      <option value={REVERSE_PROXY_TYPES.NGINX}>NGiNX</option>
      <option value={REVERSE_PROXY_TYPES.OTHER}>Some other Reverse Proxy</option>
      <option value={REVERSE_PROXY_TYPES.NONE}>I will either not use a Reverse Proxy, or I will use delegation</option>
    </select>
    <div>
      <button onClick={() => onClick(reverseProxy)}>Safety First</button>
    </div>
  </ContentWrapper>
}