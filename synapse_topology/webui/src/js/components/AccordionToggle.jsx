import React from 'react';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';

export default ({ active, children, eventKey, as }) => {

    console.log(children)
    const decoratedOnClick = active ? useAccordionToggle(eventKey) : undefined;
    const As = as;
    return <As onClick={decoratedOnClick} > {children}</As>

}
