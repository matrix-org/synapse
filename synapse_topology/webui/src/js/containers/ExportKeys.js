import { connect } from 'react-redux';

import ExportKeys from '../components/ExportKeys';

import { advanceUI } from '../actions';

const mapStateToProps = state => {

    const secretKeyLoaded = state.baseConfig.secretKeyLoaded;
    const secretKey = state.baseConfig.secretKey;
    return {
        secretKeyLoaded,
        secretKey,
    }

};

const mapDispatchToProps = dispatch => ({
    onClick: () => dispatch(advanceUI()),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps,
)(ExportKeys);