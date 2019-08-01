import React from 'react';

import style from '../../less/main.less';

import ButtonDisplay from './ButtonDisplay';
import ContentWrapper from '../containers/ContentWrapper';


export default ({ onClick }) =>
  <ContentWrapper>
    <h1>Anonymous Statistics</h1>
    <p>Would you like to report anonymouse statistics to matrix.org?</p>
    <ButtonDisplay>
      <button onClick={() => onClick(true)}>YES</button>
      <button onClick={() => onClick(false)} className={style.redButton}>NO</button>
    </ButtonDisplay>
  </ContentWrapper >