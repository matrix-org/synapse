echo 'export CIRCLE_PR_NUMBER="${CIRCLE_PR_NUMBER:-${CIRCLE_PULL_REQUEST##*/}}"' >> $BASH_ENV
source $BASH_ENV

if [[ -n "${CIRCLE_PR_NUMBER}" ]]
then
    # Update PR refs for testing.
    FETCH_REFS="${FETCH_REFS} +refs/pull/${CIRCLE_PR_NUMBER}/head:pr/${CIRCLE_PR_NUMBER}/head"
    FETCH_REFS="${FETCH_REFS} +refs/pull/${CIRCLE_PR_NUMBER}/merge:pr/${CIRCLE_PR_NUMBER}/merge"

    # Retrieve the refs
    git fetch -u origin ${FETCH_REFS}

    # Checkout PR merge ref.
    git checkout -qf "pr/${CIRCLE_PR_NUMBER}/merge"

    # Test for merge conflicts.
    git branch --merged | grep "pr/${CIRCLE_PR_NUMBER}/head" > /dev/null

fi

# Log what we are
git show -s
