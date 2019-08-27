import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import AccordionToggle from '../containers/AccordionToggle';
import { DONE_UI } from '../reducers/ui-constants';

export default ({ configDir }) => {


    return <Card>
        <AccordionToggle as={Card.Header} eventKey={DONE_UI} >
            Done
        </AccordionToggle>
        <Accordion.Collapse eventKey={DONE_UI}>
            <Card.Body>
                <p>
                    Synapse is running!
                </p>
                <p>
                    There are many settings to play with in the yaml files in <code>{configDir}</code>.
                </p>
            </Card.Body>
        </Accordion.Collapse>
    </Card>;

}