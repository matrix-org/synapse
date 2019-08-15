import { connect } from 'react-redux';

import StatsReporter from '../components/StatsReporter';

import { advanceUI, setStats, generateSecretKeys } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
    onClick: consent => {

        dispatch(advanceUI());
        dispatch(setStats(consent));
        dispatch(generateSecretKeys(consent))

    },
});

export default connect(
    null,
    mapDispathToProps,
)(StatsReporter);