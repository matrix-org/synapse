import React, { useState } from 'react';
import ContentWrapper from '../containers/ContentWrapper';

export default () => {

    return <ContentWrapper>
        <h1>Config selection</h1>
        <p>The base config has already been setup.</p>
        <p>If you want to start the installation from scratch please delete the
            config yaml.</p>
    </ContentWrapper>;

}