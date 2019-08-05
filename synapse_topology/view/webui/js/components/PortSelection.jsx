import React, { useState } from 'react';

import ContentWrapper from './ContentWrapper';

import style from '../../less/main.less';

export default ({
  serverName,
  verifyingPorts,
  fedPortInUse,
  clientPortInUse,
  canChangePorts,
  defaultFedPort,
  defaultClientPort,
  justification,
  onClickCheck,
  onClickSkipCheck,
}) => {
  if (verifyingPorts) {
    return <ContentWrapper ><h1>Verifying ports.</h1></ContentWrapper>
  }

  const [fedPort, setFedPort] = useState(defaultFedPort);
  const [clientPort, setClientPort] = useState(defaultClientPort);
  const [clientPortValid, setClientPortValid] = useState(true)
  const [fedPortValid, setFedPortValid] = useState(true)
  const [clientPortPriv, setClientPortPriv] = useState(true)
  const [fedPortPriv, setFedPortPriv] = useState(true)

  const updateValidity = (port, setValid) => setValid(
    !isNaN(port) && 0 < port && port <= 65535
  )

  const updatePriv = (port, setPriv) => setPriv(
    port < 1024
  )

  const onFederationChange = event => {
    const val = event.target.value ? event.target.value : defaultFedPort;
    setFedPort(val);
    updatePriv(val, setFedPortPriv);
    updateValidity(val, setFedPortValid);
  }

  const onClientChange = event => {
    const val = event.target.value ? event.target.value : defaultClientPort;
    setClientPort(val);
    updatePriv(val, setClientPortPriv);
    updateValidity(val, setClientPortValid);
  }

  return <ContentWrapper>
    <h1>{serverName}'s ports</h1>
    <p>
      The synapse install itself will be listening on the following ports.
    </p>
    {
      canChangePorts ?
        <p>
          Since you're using a reverse proxy you can change these to anything you
          like as long as synapse can bind to them. We recommend not using privileged
          ports within the range 0 to 1024.
        </p>
        :
        <p>
          Since you're not using a reverse proxy synapse will have to listen on
          these ports. If any of these ports are already in use (we'll test them when
          you click the button) go back and change the values you set for the ports
          there. Otherwise you're going to have to rethink your setup.
        </p>
    }

    <p>
      We will check that the port are not in use. If they are you can either
      reconfigure the server that synapse is installed on outside of this installer
      or you can change the ports as explained above.
    </p>
    <p>
      Note: we can't check the whether privileged ports are in use. If you've
      set a privileged port <b>we will skip the check</b>.
    </p>

    <h3>Federation Port</h3>
    <input
      type="text"
      onChange={onFederationChange}
      disabled={canChangePorts ? undefined : true}
      autoFocus
      placeholder={defaultFedPort}
    ></input>
    {fedPortPriv ? <p>This is a privileged port.</p> : undefined}

    <h3>Client Port</h3>
    <input
      type="text"
      onChange={onClientChange}
      disabled={canChangePorts ? undefined : true}
      autoFocus
      placeholder={defaultClientPort}
    ></input>
    {clientPortPriv ? <p>This is a privileged port.</p> : undefined}
    <div>
      <button
        disabled={clientPortValid && fedPortValid ? undefined : true}
        onClick={() => onClick(fedPort, clientPort)}
      >Verify These Ports</button>
    </div>
  </ContentWrapper>
}