import React from 'react';

import style from '../../less/main.less';
import ContentWrapper from '../containers/ContentWrapper';

export default ({ onClick }) =>
  <ContentWrapper>
    <h1>Synapse Topology</h1>
    <p>Let's get started.</p>
    <div><button onClick={onClick}>SETUP</button></div>
  </ContentWrapper>