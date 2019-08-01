import React from 'react';

import style from '../../less/main.less';

import {
  BASE_INTRO_UI,
  SERVER_NAME_UI,
  STATS_REPORT_UI,
  KEY_EXPORT_UI,
  DELEGATION_OPTIONS_UI,
  WELL_KNOWN_UI,
  DNS_UI,
  WORKER_UI,
  ACME_UI,
  REVERSE_PROXY_UI,
  PORT_SELECTION_UI,
  REVERSE_PROXY_TEMPLATE_UI,
  LOADING_UI,
  ERROR_UI,
  DELEGATION_SERVER_NAME_UI,
} from '../reducers/ui_constants';

import IntroUi from '../containers/BaseIntro';
import ServerName from '../containers/ServerName';
import StatsReporter from '../containers/StatsReporter';
import ExportKeys from '../containers/ExportKeys';

import Error from '../components/Error';
import Loading from '../components/Loading';
import DelegationOptions from '../containers/DelegationOptions';
import DelegationServerName from '../containers/DelegationServerName';
import ReverseProxy from './ReverseProxy';

export default ({ active_ui, dispatch }) => {
  console.log(`switching to ui ${active_ui}`)
  console.log(DELEGATION_OPTIONS_UI)
  switch (active_ui) {
    case LOADING_UI:
      return <Loading />
    case ERROR_UI:
      return <Error />
    case BASE_INTRO_UI:
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
    case REVERSE_PROXY_UI:
      return <ReverseProxy />
    case WELL_KNOWN_UI:
    case DNS_UI:
    case WORKER_UI:
    case ACME_UI:
    case PORT_SELECTION_UI:
    case REVERSE_PROXY_TEMPLATE_UI:
    default:
      return <h1>how did i get here?</h1>
  }
}