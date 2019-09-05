/* eslint-disable max-len */
import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';

import { PORT_SELECTION_UI } from '../reducers/ui-constants';

import AccordionToggle from '../containers/AccordionToggle';
import ContentWrapper from '../containers/ContentWrapper';

import { nextUI } from '../reducers/setup-ui-reducer';
import InlineError from './InlineError';

export default ({
    servername,
    verifyingPorts,
    fedPortInUse,
    clientPortInUse,
    canChangePorts,
    defaultFedPort,
    defaultClientPort,
    onClick,
}) => {

    if (verifyingPorts) {

        return <ContentWrapper><h1>Verifying ports.</h1></ContentWrapper>

    }
    const [fedPort, setFedPort] = useState();
    const [clientPort, setClientPort] = useState();

    const [clientPortValid, setClientPortValid] = useState(true)
    const [fedPortValid, setFedPortValid] = useState(true)


    const updateValidity = (port, setValid) => setValid(
        !isNaN(port) && 0 < port && port <= 65535,
    )


    const onFederationChange = event => {

        const val = event.target.value ? event.target.value : defaultFedPort;
        setFedPort(val);
        updateValidity(val, setFedPortValid);

    }

    const onClientChange = event => {

        const val = event.target.value ? event.target.value : defaultClientPort;
        setClientPort(val);
        updateValidity(val, setClientPortValid);

    }

    const toggle = useAccordionToggle(nextUI(PORT_SELECTION_UI));

    const fedPortError = fedPortInUse ?
        "This port is in use" :
        !fedPortValid ? "Invalid port" :
            undefined;

    const clientPortError = clientPortInUse ?
        "This port is in use" :
        !clientPortValid ? "Invalid port" :
            undefined;

    const fedPortPriv = fedPort ? fedPort < 1024 : defaultFedPort < 1024
    const clientPortPriv = clientPort ? clientPort < 1024 : defaultClientPort < 1024
    return <Card>
        <AccordionToggle as={Card.Header} eventKey={PORT_SELECTION_UI}>
            {servername ? servername + "'s ports" : "Ports"}
        </AccordionToggle>
        <Accordion.Collapse eventKey={PORT_SELECTION_UI}>
            <Card.Body>

                <p>
                    Synapse will be listening on the following ports on localhost.
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
                            you click the button) you will either need to reconfigure the ports used on
                            localhost, setup up delegation or use a reverse proxy.
                        </p>
                }

                <p>
                    We will check that the ports are not in use.
                </p>
                <p>
                    Note: we can't check whether privileged ports are in use. If you've
                    set a privileged port <b>we will skip the check for that port</b>.
                </p>

                <h6>Federation Port</h6>
                <InlineError error={fedPortError}>
                    <input
                        type="text"
                        onChange={onFederationChange}
                        disabled={canChangePorts ? undefined : true}
                        autoFocus
                        placeholder={defaultFedPort}
                    />
                </InlineError>
                {fedPortPriv ? <p>This is a privileged port.</p> : undefined}
                <h6>Client Port</h6>
                <InlineError error={clientPortError}>
                    <input
                        type="text"
                        onChange={onClientChange}
                        disabled={canChangePorts ? undefined : true}
                        autoFocus
                        placeholder={defaultClientPort}
                    />
                </InlineError>
                {clientPortPriv ? <p>This is a privileged port.</p> : undefined}
                <div>
                    <button
                        disabled={clientPortValid && fedPortValid ? undefined : true}
                        onClick={() => onClick(
                            fedPort ? parseInt(fedPort) : defaultFedPort,
                            clientPort ? parseInt(clientPort) : defaultClientPort,
                            toggle,
                        )}
                    >Verify These Ports</button>
                </div>
            </Card.Body>
        </Accordion.Collapse>
    </Card>

}
