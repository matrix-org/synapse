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

    const [body, setBody] = useState();

    const revProxyBody = <Card.Body>
        <ReverseProxySampleConfig />
        <button
            onClick={
                () => delegationType != DELEGATION_TYPES.LOCAL ?
                    setBody(delegationBody) :
                    setBody(finishedBody)
            }
        >Next</button>
    </Card.Body >

    const delegationBody = <Card.Body>
        <DelegationSampleConfig />
        <button
            onClick={
                () => setBody(finishedBody)
            }
        >Next</button>
    </Card.Body>

    const finishedBody = <Card.Body>
        <p>You done</p>
        <button onClick={onClick}>Start Synapse</button>
    </Card.Body>

    if (!body) {

        setBody(
            tlsType == TLS_TYPES.REVERSE_PROXY ?
                revProxyBody :
                delegationType != DELEGATION_TYPES.LOCAL ?
                    delegationBody :
                    finishedBody,
        )

    }

    return <Card>
        <AccordionToggle as={Card.Header} eventKey={COMPLETE_UI}>
            Setup Complete
        </AccordionToggle>
        <Accordion.Collapse eventKey={COMPLETE_UI}>
            {body}
        </Accordion.Collapse>
    </Card>

}
