import React from 'react';

import style from '../../less/main.less';

import {
  SETUP_INTRO_UI,
  SERVER_NAME_UI,
  STATS_REPORT_UI,
  KEY_EXPORT_UI,
  DELEGATION_OPTIONS_UI,
  WELL_KNOWN_UI,
  DNS_UI,
  WORKER_UI,
  TLS_UI,
  REVERSE_PROXY_UI,
  PORT_SELECTION_UI,
  REVERSE_PROXY_TEMPLATE_UI,
  LOADING_UI,
  ERROR_UI,
  DELEGATION_SERVER_NAME_UI,
  TLS_CERTPATH_UI,
  DELEGATION_PORT_SELECTION_UI,
  DELEGATION_TEMPLATE_UI,
  DATABASE_UI,
} from '../reducers/ui_constants';

import WalkThrough from './WalkThrough'
import Error from './Error';
import Loading from './Loading';

import IntroUi from '../containers/BaseIntro';
import ServerName from '../containers/ServerName';
import StatsReporter from '../containers/StatsReporter';
import ExportKeys from '../containers/ExportKeys';
import DelegationOptions from '../containers/DelegationOptions';
import DelegationServerName from '../containers/DelegationServerName';
import ReverseProxy from '../containers/ReverseProxy';
import TLS from '../containers/TLS';
import TLSCertPath from '../containers/TLSCertPath';
import DelegationPortSelection from '../containers/DelegationPortSelection';
import PortSelection from '../containers/PortSelection';
import ReverseProxySampleConfig from '../containers/ReverseProxySampleConfig';
import DelegationSampleConfig from '../containers/DelegationSampleConfig';
import Database from '../containers/Database';
import ConfigSelector from './ConfigSelector';

const block_mapping = ui_block => {
  console.log(`fetching ${ui_block}`)
  switch (ui_block) {
    case LOADING_UI:
      return <Loading />
    case ERROR_UI:
      return <Error />
    case SETUP_INTRO_UI:
      return < IntroUi />
    case SERVER_NAME_UI:
      return <ServerName />
    case STATS_REPORT_UI:
      return <StatsReporter />
    case KEY_EXPORT_UI:
      return <ExportKeys />
    case DELEGATION_OPTIONS_UI:
      return <DelegationOptions />
    case DELEGATION_SERVER_NAME_UI:
      return <DelegationServerName />
    case DELEGATION_PORT_SELECTION_UI:
      return <DelegationPortSelection />
    case REVERSE_PROXY_UI:
      return <ReverseProxy />
    case TLS_UI:
      return <TLS />
    case TLS_CERTPATH_UI:
      return <TLSCertPath />
    case PORT_SELECTION_UI:
      return <PortSelection />
    case REVERSE_PROXY_TEMPLATE_UI:
      return <ReverseProxySampleConfig />
    case DELEGATION_TEMPLATE_UI:
      return <DelegationSampleConfig />
    case DATABASE_UI:
      return <Database />
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
  } else {
    console.log(setup_ui);
    return <WalkThrough>
      {setup_ui.active_blocks.map(block_mapping)}
    </WalkThrough>
  }
}