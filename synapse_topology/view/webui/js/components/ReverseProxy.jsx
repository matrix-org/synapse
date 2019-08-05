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