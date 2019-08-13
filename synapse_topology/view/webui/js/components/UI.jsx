import React from 'react';

import style from '../../less/main.less';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';

import {
  SETUP_INTRO_UI,
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
} from '../reducers/ui_constants';

import Error from './Error';
import Loading from './Loading';

import IntroUi from '../containers/BaseIntro';
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

const block_mapping = ui_block => {
  console.log(`fetching ${ui_block}`)
  switch (ui_block) {
    case LOADING_UI:
      return <Loading key={ui_block} />
    case ERROR_UI:
      return <Error key={ui_block} />
    case SETUP_INTRO_UI:
      return < IntroUi key={ui_block} />
    case SERVER_NAME_UI:
      return <ServerName key={ui_block} />
    case STATS_REPORT_UI:
      return <StatsReporter key={ui_block} />
    case KEY_EXPORT_UI:
      return <ExportKeys key={ui_block} />
    case DELEGATION_OPTIONS_UI:
      return <DelegationOptions key={ui_block} />
    case TLS_UI:
      return <TLS key={ui_block} />
    case PORT_SELECTION_UI:
      return <PortSelection key={ui_block} />
    case REVERSE_PROXY_TEMPLATE_UI:
      return <ReverseProxySampleConfig key={ui_block} />
    case DELEGATION_TEMPLATE_UI:
      return <DelegationSampleConfig key={ui_block} />
    case DATABASE_UI:
      return <Database key={ui_block} />
    case COMPLETE_UI:
      return <CompleteSetup key={ui_block} />
    default:
      return <h1>how did i get here?</h1>
  }
}

export default ({ setup_ui, config_ui, base_config }) => {

  if (!base_config.base_config_checked) {
    return <Loading />
  }

  if (base_config.setup_done) {
    console.log(`switching to ui ${config_ui}`);
    return <ConfigSelector></ConfigSelector>
  }

  if (!base_config.setup_done) {
    console.log(setup_ui);
    return <Accordion defaultActiveKey="0">
      {setup_ui.active_blocks.map(block_mapping)}
    </Accordion >
  }
}