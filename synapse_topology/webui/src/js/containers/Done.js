import { connect } from 'react-redux';

import Done from '../components/Done';


const mapStateToProps = (state, ownProps) => ({
    configDir: state.baseConfig.configDir,
});

const mapDispathToProps = (dispatch) => ({
});

export default connect(
    mapStateToProps,
    mapDispathToProps,
)(Done);