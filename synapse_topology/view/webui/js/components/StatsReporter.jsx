import React from 'react';

import style from '../../less/main.less';

import ButtonDisplay from './ButtonDisplay';
import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import { STATS_REPORT_UI } from '../reducers/ui_constants';


export default ({ onClick }) =>
  <Card>
    <Accordion.Toggle as={Card.Header} eventKey={STATS_REPORT_UI}>
      Anonymous Statistics
    </Accordion.Toggle>
    <Accordion.Collapse eventKey={STATS_REPORT_UI}>
      <Card.Body>
        <p>
          Would you like to report anonymous statistics to matrix.org?
          Your server will send anonymised, aggregated statistics to matrix.org
          on user usage so we can measure the health of the Matrix ecosystem.
        </p>
        <ButtonDisplay>
          <button onClick={() => onClick(true)}>YES</button>
          <button onClick={() => onClick(false)} className={style.redButton}>NO</button>
        </ButtonDisplay>
      </Card.Body>
    </Accordion.Collapse>
  </Card >