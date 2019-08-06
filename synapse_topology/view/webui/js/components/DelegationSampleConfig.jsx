import React from 'react';

import ContentWrapper from '../containers/ContentWrapper';
import ButtonDisplay from './ButtonDisplay';
import DownloadOrCopy from './DownloadOrCopy';
import { REVERSE_PROXY_TYPES, DELEGATION_TYPES } from '../actions/constants';

export default (delegationType, serverConfig, clientConfig, fileName, serverName, onClick) => {
  const delegationExplanation = delegationType == DELEGATION_TYPES.DNS ?
    "You will need to add the following SRV record to your DNS zone." :
    `You'll need to host the following at https://${serverName}/.well-known/matrix/server`
  return <ContentWrapper>
    <h1>Configure delegation</h1>
    <p>
      The delegation configuration needs to take place outside the installer.
    </p>
    {delegationExplanation}
    <code>
      {sampleConfig}
    </code>
    <DownloadOrCopy content={sampleConfig} fileName={fileName} />
    <ButtonDisplay>
      <button onClick={onClick}>Continue</button>
    </ButtonDisplay>
  </ContentWrapper>;
}