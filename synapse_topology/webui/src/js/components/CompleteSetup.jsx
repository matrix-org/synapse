import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';

import ReverseProxySampleConfig from '../containers/ReverseProxySampleConfig'
import DelegationSampleConfig from '../containers/DelegationSampleConfig';
import AccordionToggle from '../containers/AccordionToggle';

import { TLS_TYPES, DELEGATION_TYPES } from '../actions/constants';
import { COMPLETE_UI } from '../reducers/ui-constants';

export default ({
    tlsType,
    delegationType,
    onClick,
}) => {


    const revProxyBody = <Card.Body>
        <ReverseProxySampleConfig />
        <button
            onClick={() => setBody(body + 1)}
        >Next</button>
    </Card.Body >

    const delegationBody = <Card.Body>
        <DelegationSampleConfig />
        <button
            onClick={() => setBody(body + 1)}
        >Next</button>
    </Card.Body>

    const finishedBody = <Card.Body>
        <p>You done</p>
        <button onClick={onClick}>Start Synapse</button>
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
