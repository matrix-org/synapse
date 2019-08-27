import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import { SERVER_NAME_UI } from '../reducers/ui-constants';
import AccordionToggle from '../containers/AccordionToggle';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';
import { nextUI } from '../reducers/setup-ui-reducer';
import InlineError from './InlineError';

export default ({ onClick }) => {

    const [servername, setServerName] = useState("");
    const [serverNameValid, setServerNameValid] = useState(true);
    const validator = /^[0-9a-zA-Z.-]+$/;

    const onChange = event => {

        setServerName(event.target.value);
        setServerNameValid(validator.test(event.target.value));

    };


    const toggle = useAccordionToggle(nextUI(SERVER_NAME_UI));
    const decoratedOnClick = () => {

        onClick(servername);
        toggle();

    }

    return <Card>
        <AccordionToggle as={Card.Header} eventKey={SERVER_NAME_UI} >
            Name your server
        </AccordionToggle>
        <Accordion.Collapse eventKey={SERVER_NAME_UI}>
            <Card.Body>
                <p>
                    Your server name usually matches your domain. For example, the
                    matrix.org server is simply called `matrix.org`.
                        </p>
                <p>
                    Your server name will be used to establish User IDs (e.g.
                    `@user:server.name`) and Room Aliases (e.g. `#room:server.name`).
                </p>
                <InlineError error={!serverNameValid ? "The servername may only be alphanumeric characters" : undefined}>
                    <input
                        type="text"
                        onChange={onChange}
                        autoFocus
                        placeholder="Enter server name"
                    />
                </InlineError>
                <div>
                    <button
                        disabled={servername && serverNameValid ? undefined : true}
                        onClick={decoratedOnClick}
                    >
                        Next
                    </button>
                </div>
            </Card.Body>
        </Accordion.Collapse>
    </Card>;

}