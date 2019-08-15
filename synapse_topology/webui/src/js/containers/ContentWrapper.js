import { connect } from 'react-redux';

import ContentWrapper from '../components/ContentWrapper';

const mapStateToProps = (state, { children }) => ({
    servername: state.baseConfig.servername,
    children,
});


const mapDispatchToProps = (dispatch) => ({
});

export default connect(
    mapStateToProps,
)(ContentWrapper);