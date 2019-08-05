import React, { useState } from 'react';

import ContentWrapper from './ContentWrapper';

import {
  REVERSE_PROXY_TYPES
} from '../actions/constants'


export default ({ onClick }) => {
  const [reverseProxy, setReverseProxy] = useState(REVERSE_PROXY_TYPES.NONE);

  const onChange = event => {
    setReverseProxy(event.target.value);
  }

  return <ContentWrapper>
    <h1>Reverse Proxy</h1>
    <p>
      Please choose the reverse proxy you're using. This is just so we can provide
      you with a template later, if you already know how you're going to set yours
      up don't worry too much about this.
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