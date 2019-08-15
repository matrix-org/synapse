import { connect } from 'react-redux';

import AccordionToggle from '../components/AccordionToggle';

const mapStateToProps = (state, { eventKey, as, children }) => ({
    active: state.setupUI.activeBlocks.includes(eventKey),
    eventKey,
    as,
    children,
});

const mapDispathToProps = (dispatch) => ({
});

export default connect(
    mapStateToProps,
    mapDispathToProps,
)(AccordionToggle);