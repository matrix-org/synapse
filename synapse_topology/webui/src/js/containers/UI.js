import { connect } from 'react-redux';
import UI from '../components/UI';

const mapStateToProps = ({ setupDone, setupUI, configUI, baseConfig }) => ({
    setupDone,
    setupUI,
    configUI,
    baseConfig,
})


const mapDispathToProps = (dispatch, ownProps) => ({

})

export default connect(
    mapStateToProps,
)(UI)