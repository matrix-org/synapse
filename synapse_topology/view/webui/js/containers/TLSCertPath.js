import { connect } from 'react-redux';

import TLSCertPath from '../components/TLSCertPath';

import { set_tls_cert_paths, upload_tls_cert_files } from '../actions';

const mapStateToProps = state => ({
  testingCertPaths: state.base_config.testing_cert_paths,
  uploadingCertPaths: state.base_config.uploading_certs,
  certPathInvalid: state.base_config.cert_path_invalid,
  certKeyPathInvalid: state.base_config.cert_key_path_invalid,
});

const mapDispathToProps = dispatch => ({
  onClickCertPath: (cert_path, cert_key_path) => {
    dispatch(set_tls_cert_paths(cert_path, cert_key_path));
  },
  onClickCertUpload: (tls_cert_file, tls_key_file) => {
    dispatch(upload_tls_cert_files(tls_cert_file, tls_key_file));
  },
});

export default connect(
  mapStateToProps,
  mapDispathToProps
)(TLSCertPath)