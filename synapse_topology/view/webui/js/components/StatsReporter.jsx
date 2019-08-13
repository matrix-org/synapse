import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';

import { STATS_REPORT_UI } from '../reducers/ui_constants';
import AccordionToggle from '../containers/AccordionToggle';


export default ({ onClick }) => {
  const [consent, setConsent] = useState(true);

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
        <button onClick={() => onClick(consent)}>Next</button>
      </Card.Body>
    </Accordion.Collapse>
  </Card >
}