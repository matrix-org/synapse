import { connect } from 'react-redux';

import Database from '../components/Database';
import { setDatabase, advanceUI } from '../actions';

const mapStateToProps = (state) => {
};


const mapDispatchToProps = (dispatch) => ({
    onClick: database => {

        dispatch(setDatabase(database));
        dispatch(advanceUI());

    },
});

export default connect(
    null,
    mapDispatchToProps,
)(Database);