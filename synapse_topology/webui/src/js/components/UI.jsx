import React from 'react';

import style from '../../scss/main.scss';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';

import {
    SERVER_NAME_UI,
    STATS_REPORT_UI,
    KEY_EXPORT_UI,
    DELEGATION_OPTIONS_UI,
    TLS_UI,
    PORT_SELECTION_UI,
    REVERSE_PROXY_TEMPLATE_UI,
    LOADING_UI,
    ERROR_UI,
    DELEGATION_TEMPLATE_UI,
    DATABASE_UI,
    COMPLETE_UI,
    SETUP_ORDER,
} from '../reducers/ui-constants';

import Error from './Error';
import Loading from './Loading';

import BaseIntro from '../containers/BaseIntro';
import ServerName from '../containers/ServerName';
import StatsReporter from '../containers/StatsReporter';
import ExportKeys from '../containers/ExportKeys';
import DelegationOptions from '../containers/DelegationOptions';
import TLS from '../containers/TLS';
import PortSelection from '../containers/PortSelection';
import ReverseProxySampleConfig from '../containers/ReverseProxySampleConfig';
import DelegationSampleConfig from '../containers/DelegationSampleConfig';
import Database from '../containers/Database';
import ConfigSelector from './ConfigSelector';
import CompleteSetup from '../containers/CompleteSetup';
import ContentWrapper from '../containers/ContentWrapper';

const blockMapping = uiBlock => {

    switch (uiBlock) {

        case LOADING_UI:
            return <Loading key={uiBlock} />
        case ERROR_UI:
            return <Error key={uiBlock} />
        case SERVER_NAME_UI:
            return <ServerName key={uiBlock} />
        case STATS_REPORT_UI:
            return <StatsReporter key={uiBlock} />
        case KEY_EXPORT_UI:
            return <ExportKeys key={uiBlock} />
        case DELEGATION_OPTIONS_UI:
            return <DelegationOptions key={uiBlock} />
        case TLS_UI:
            return <TLS key={uiBlock} />
        case PORT_SELECTION_UI:
            return <PortSelection key={uiBlock} />
        case REVERSE_PROXY_TEMPLATE_UI:
            return <ReverseProxySampleConfig key={uiBlock} />
        case DELEGATION_TEMPLATE_UI:
            return <DelegationSampleConfig key={uiBlock} />
        case DATABASE_UI:
            return <Database key={uiBlock} />
        case COMPLETE_UI:
            return <CompleteSetup key={uiBlock} />
        default:
            return <h1>how did i get here?</h1>

    }

}

export default ({ setupUI, configUI, baseConfig }) => {

    if (!baseConfig.baseConfigChecked) {

        return <Loading />

    }

    if (baseConfig.setupDone) {

        console.log(`switching to ui ${configUI}`);
        return <ConfigSelector></ConfigSelector>

    }

    if (!baseConfig.setupDone) {

        return <ContentWrapper>
            <Accordion>
                <BaseIntro />
                <div style={setupUI.activeBlocks.length ? undefined : { display: "none" }}>
                    {SETUP_ORDER.map(blockMapping)}
                </div>
            </Accordion>
        </ContentWrapper>

    }

}