import React from 'react';

import ContentWrapper from '../containers/ContentWrapper';
import ButtonDisplay from './ButtonDisplay';
import DownloadOrCopy from './DownloadOrCopy';
import { DELEGATION_TYPES } from '../actions/constants';

export default ({
  delegationType,
  serverConfig,
  clientConfig,
  serverConfigFileName,
  clientConfigFileName,
  serverName,
  onClick
}) => {
  if (delegationType == DELEGATION_TYPES.DNS) {

    return <ContentWrapper>
      <h1>ConfigureDelegation</h1>
      <p>
        You will need to add the following SRV record to your DNS zone.
      </p>
      <pre>
        <code>
          {clientConfig}
        </code>
      </pre>
      <DownloadOrCopy content={clientConfig} fileName={clientConfigFileName} />
      <ButtonDisplay>
        <button onClick={onClick}>Continue</button>
      </ButtonDisplay>
    </ContentWrapper>

  } else {

    return <ContentWrapper>
      <h1>Configure delegation</h1>
      <p>
        The delegation configuration needs to take place outside the installer.
      </p>
      <p>
        You'll need to host the following at https://{serverName}/.well-known/matrix/server
      </p>
      <pre>
        <code>
          {serverConfig}
        </code>
      </pre>
      <DownloadOrCopy content={serverConfig} fileName={serverConfigFileName} />
      <p>
        You'll also need to host the following at https://{serverName}/.well-known/matrix/client
      </p>
      <pre>
        <code>
          {clientConfig}
        </code>
      </pre>
      <DownloadOrCopy content={clientConfig} fileName={clientConfigFileName} />
      <ButtonDisplay>
        <button onClick={onClick}>Continue</button>
      </ButtonDisplay>
    </ContentWrapper>;

  }
}