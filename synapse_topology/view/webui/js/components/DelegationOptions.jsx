import React from 'react';

import style from '../../less/main.less';
import ContentWrapper from '../containers/ContentWrapper';
import ButtonDisplay from './ButtonDisplay';

export default ({ servername, clickLocal, clickWellKnown, clickDNS }) => {
  const local_button_text = `This server is ${servername}`;
  return <ContentWrapper>
    <h1>Delegation</h1>
    <p>Other federation servers will connect to {servername}:8448 over the network.</p>
    <p>
      If you'd like the synapse install to be hosted on a different server
      to the one known on the network by '{servername}' you can use delegation.
    </p>
    <p>
      Otherwise click '{local_button_text}'.
    </p>
    <p>There are two forms of delegation: </p>
    <h3>.well_known delegation</h3>
    <p>
      {servername} provides the url https://{servername}/.well-known/matrix/server
      which gives federating servers information about how to contact the actual server
      hosting the synapse install. (Don't worry! We'll print out the .well-known file for you later.)
    </p>
    <h3>DNS SRV delegation</h3>
    <p>
      You will need access to {servername}'s domain zone DNS records. This method
      also requires the synapse install's server to provide a valid TLS cert for {servername}
    </p>
    <p>
      You will need to add an SRV record to {servername}'s DNS zone. (Once again, we'll print
      the SRV record out for you later.)
    </p>

    <h3>More info</h3>
    <p>
      Confused? I am too. Maybe <a href="https://github.com/matrix-org/synapse/blob/master/docs/federate.md" target="_blank">
        this can answer some of your questions.
      </a>
    </p>
    <ButtonDisplay>
      <button onClick={clickLocal}>{local_button_text}</button>
      <button onClick={clickWellKnown}>Use 'well known'</button>
      <button onClick={clickDNS}>Use DNS</button>
    </ButtonDisplay>
  </ContentWrapper>;
}