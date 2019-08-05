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
  TLS_UI,
  REVERSE_PROXY_UI,
  PORT_SELECTION_UI,
  REVERSE_PROXY_TEMPLATE_UI,
  LOADING_UI,
  ERROR_UI,
  DELEGATION_SERVER_NAME_UI,
  TLS_CERTPATH_UI,
  DELEGATION_PORT_SELECTION_UI,
} from '../reducers/ui_constants';

import Error from '../components/Error';
import Loading from '../components/Loading';

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

export default ({ active_ui, dispatch }) => {
  console.log(`switching to ui ${active_ui}`)
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
    case DELEGATION_PORT_SELECTION_UI:
      return <DelegationPortSelection />
    case REVERSE_PROXY_UI:
      return <ReverseProxy />
    case TLS_UI:
      return <TLS />
    case TLS_CERTPATH_UI:
      return <TLSCertPath />
    case WELL_KNOWN_UI:
    case DNS_UI:
    case WORKER_UI:
    case PORT_SELECTION_UI:
    case REVERSE_PROXY_TEMPLATE_UI:
    default:
      return <h1>how did i get here?</h1>
  }
}