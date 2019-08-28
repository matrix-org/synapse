import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';

import ReverseProxySampleConfig from '../containers/ReverseProxySampleConfig'
import DelegationSampleConfig from '../containers/DelegationSampleConfig';
import AccordionToggle from '../containers/AccordionToggle';
import InlineError from '../components/InlineError';

import { TLS_TYPES, DELEGATION_TYPES } from '../actions/constants';
import { COMPLETE_UI } from '../reducers/ui-constants';
import { nextUI } from '../reducers/setup-ui-reducer';

export default ({
    tlsType,
    delegationType,
    synapseStartFailed,
    configDir,
    onClick,
}) => {
    const toggle = useAccordionToggle(nextUI(COMPLETE_UI));

    const decoratedOnClick = () => {
        onClick(toggle);
    }

    const [revProxyDownloaded, setRevProxyDownloaded] = useState(false);
    const [delegationDownloaded, setDelegationDownloaded] = useState(false);

    const revProxyBody = <Card.Body>
        <ReverseProxySampleConfig onClick={() => setRevProxyDownloaded(true)} />
        <button
            disabled={!revProxyDownloaded}
            onClick={() => setBody(body + 1)}
        >Next</button>
    </Card.Body >

    const delegationBody = <Card.Body>
        <DelegationSampleConfig onClick={() => setDelegationDownloaded(true)} />
        <button
            disabled={!delegationDownloaded}
            onClick={() => setBody(body + 1)}
        >Next</button>
    </Card.Body>


    const finishedBody = <Card.Body>
        <InlineError error={synapseStartFailed ? "Couldn't start synapse." : undefined}>
            <button onClick={decoratedOnClick}>Start Synapse</button>
        </InlineError>
        <hr />
        <p>
            In future use <a href="https://manpages.debian.org/testing/matrix-synapse/synctl.1.en.html">
                synctl</a> to start and stop synapse. Use the following to start synapse again:

        </p>

        <pre>
            <code>
                synctl start {configDir}
            </code>
        </pre>
    </Card.Body>

    const show = [];
    const [body, setBody] = useState(0);



    if (tlsType == TLS_TYPES.REVERSE_PROXY) {

        show.push(revProxyBody);

    }
    if (delegationType != DELEGATION_TYPES.LOCAL) {

        show.push(delegationBody)

    }
    show.push(finishedBody)


    return <Card>
        <AccordionToggle as={Card.Header} eventKey={COMPLETE_UI}>
            Setup Complete
        </AccordionToggle>
        <Accordion.Collapse eventKey={COMPLETE_UI}>
            {show[body]}
        </Accordion.Collapse>
    </Card>

}
