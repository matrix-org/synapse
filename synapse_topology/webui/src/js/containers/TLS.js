import { connect } from 'react-redux';

import TLS from '../components/TLS';

import { advance_ui, set_tls, set_tls_cert_paths, set_tls_cert_files, set_reverse_proxy } from '../actions';

import { TLS_TYPES } from '../actions/constants';

const mapStateToProps = (state, ownProps) => ({
  testingCertPaths: state.base_config.testing_cert_paths,
  uploadingCertPaths: state.base_config.uploading_certs,
  certPathInvalid: state.base_config.cert_path_invalid,
  certKeyPathInvalid: state.base_config.cert_key_path_invalid,
});

const mapDispathToProps = (dispatch) => ({
  onClickACME: () => {
    dispatch(advance_ui(TLS_TYPES.ACME));
    dispatch(set_tls(TLS_TYPES.ACME));
  },
  onClickReverseProxy: proxy_type => {
    dispatch(advance_ui());
    dispatch(set_tls(TLS_TYPES.REVERSE_PROXY))
    dispatch(set_reverse_proxy(proxy_type))
  },
  onClickCertPath: (cert_path, cert_key_path, callback) => {
    dispatch(set_tls_cert_paths(cert_path, cert_key_path, callback));
  },
  onClickCertUpload: (tls_cert_file, tls_key_file, callback) => {
    dispatch(set_tls_cert_files(tls_cert_file, tls_key_file));
    callback();
  },
});

export default connect(
  null,
  mapDispathToProps
)(TLS)