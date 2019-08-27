import { connect } from 'react-redux';

import AccordionToggle from '../components/AccordionToggle';
import { resetUI } from '../actions';
import { DONE_UI } from '../reducers/ui-constants';

const mapStateToProps = (state, { eventKey, as, children }) => ({
    active: state.setupUI.activeBlocks.includes(eventKey) && state.setupUI.activeBlocks[state.setupUI.activeBlocks.length - 1] != DONE_UI,
    open: state.setupUI.activeBlocks[state.setupUI.activeBlocks.length - 1] == eventKey,
    eventKey,
    as,
    children,
});

const mapDispathToProps = (dispatch, { eventKey }) => ({
    reset: () => dispatch(resetUI(eventKey)),
});

export default connect(
    mapStateToProps,
    mapDispathToProps,
)(AccordionToggle);