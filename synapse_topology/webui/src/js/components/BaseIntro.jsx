import React from 'react';

import ContentWrapper from '../containers/ContentWrapper';
import ButtonDisplay from './ButtonDisplay';

export default ({ onClick }) =>
    <ContentWrapper>
        <h1>Synapse Topology</h1>
        <p>Let's get started.</p>
        <ButtonDisplay><button onClick={onClick}>SETUP</button></ButtonDisplay>
    </ContentWrapper>