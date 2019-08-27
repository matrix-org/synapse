import { connect } from 'react-redux';

import TLS from '../components/TLS';

import {
    advanceUI,
    setTls,
    setTlsCertPaths,
    setTlsCertFiles,
    setReverseProxy,
} from '../actions';

import { TLS_TYPES } from '../actions/constants';

const mapStateToProps = (state, ownProps) => ({
    testingCertPaths: state.baseConfig.testingCertPaths,
    uploadingCertPaths: state.baseConfig.uploadingCerts,
    certPathInvalid: state.baseConfig.certPathInvalid,
    certKeyPathInvalid: state.baseConfig.certKeyPathInvalid,
});

const mapDispathToProps = (dispatch) => ({
    onClickACME: () => {

        dispatch(advanceUI(TLS_TYPES.ACME));
        dispatch(setTls(TLS_TYPES.ACME));

    },
    onClickReverseProxy: proxyType => {

        dispatch(advanceUI());
        dispatch(setTls(TLS_TYPES.REVERSE_PROXY))
        dispatch(setReverseProxy(proxyType))

    },
    onClickCertPath: (certPath, certKeyPath, callback) => {

        dispatch(setTlsCertPaths(certPath, certKeyPath, callback));

    },
    onClickCertUpload: (tlsCertFile, tlsKeyFile, callback) => {

        dispatch(setTlsCertFiles(tlsCertFile, tlsKeyFile));
        callback();

    },
});

export default connect(
    mapStateToProps,
    mapDispathToProps,
)(TLS)