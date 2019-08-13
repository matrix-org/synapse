import React from 'react';

import ContentWrapper from '../containers/ContentWrapper';
import ButtonDisplay from './ButtonDisplay';
import DownloadOrCopy from './DownloadOrCopy';
import { REVERSE_PROXY_TYPES } from '../actions/constants';

export default ({ proxyType, sampleConfig, fileName }) => {
  return <ContentWrapper>
    <h1>Configure the ReverseProxy</h1>
    <p>
      It's time for you to setup the reverse proxy outside of this installer.
    </p>
    {
      proxyType == REVERSE_PROXY_TYPES.OTHER ?
        <p>
          Here's a sample config for Apache. Since you chose 'other' for your reverse proxy.
          You'll have to figure it out for yourself. We believe in you.
        </p>
        :
        <p>
          We can't do it for you
        but here's the sample configuration for your {proxyType} proxy.
        </p>
    }
    <pre>
      <code>
        {sampleConfig}
      </code>
    </pre>
    <DownloadOrCopy content={sampleConfig} fileName={fileName} />
  </ContentWrapper>;
}