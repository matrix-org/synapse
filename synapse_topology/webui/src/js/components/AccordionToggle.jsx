import React from 'react';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';
import { reset } from 'ansi-colors';

export default ({ active, children, eventKey, as, reset }) => {

    const toggle = useAccordionToggle(eventKey);
    const decoratedOnClick = () => {

        if (active) {

            toggle();
            reset();

        }

    }
    const As = as;
    return <As onClick={decoratedOnClick} active={active}> {children}</As>

}
