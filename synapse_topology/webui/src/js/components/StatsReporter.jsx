import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';

import { STATS_REPORT_UI } from '../reducers/ui-constants';
import AccordionToggle from '../containers/AccordionToggle';
import { nextUI } from '../reducers/setup-ui-reducer';


export default ({ onClick }) => {

    const [consent, setConsent] = useState(false);
    const toggle = useAccordionToggle(nextUI(STATS_REPORT_UI));
    const decoratedOnClick = () => {

        toggle();
        onClick(consent);

    }

    return <Card>
        <AccordionToggle as={Card.Header} eventKey={STATS_REPORT_UI}>
            Anonymous Statistics
        </AccordionToggle>
        <Accordion.Collapse eventKey={STATS_REPORT_UI}>
            <Card.Body>
                <p>
                    Would you like to report anonymous statistics to matrix.org?
                    Your server will send anonymised, aggregated statistics to matrix.org
                    on user usage so we can measure the health of the Matrix ecosystem.
                </p>
                <label>
                    <input
                        type="checkbox"
                        onChange={event => setConsent(event.target.checked)}
                    />
                    Yes, send anonymous statistics
                </label>
                <button onClick={decoratedOnClick}>Next</button>
            </Card.Body>
        </Accordion.Collapse>
    </Card>

}