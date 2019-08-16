import React from 'react';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';
import { reset } from 'ansi-colors';
import Chevron from './Chevron';

export default ({ active, open, children, eventKey, as, reset }) => {

    const toggle = useAccordionToggle(eventKey);
    const decoratedOnClick = () => {

        if (active) {

            toggle();
            reset();

        }

    }
    const As = as;
    return <div className={active ? "active-card-header" : "inactive-card-header"}>
        <As onClick={decoratedOnClick}> {children} <Chevron open={open} /></As>
    </div>

}
