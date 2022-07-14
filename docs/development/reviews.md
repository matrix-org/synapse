Some notes on how we do reviews
===============================

The Synapse team works off a shared review queue -- any new pull requests for
Synapse (or related projects) has a review requested from the entire team. Team
members should process this queue using the following rules:

* Any high urgency pull requests (e.g. fixes for broken continuous integration
  or fixes for release blockers);
* Follow-up reviews for pull requests which have previously received reviews;
* Any remaining pull requests.

For the latter two categories above, older pull requests should be prioritised.

It is explicit that there is no priority given to pull requests from the team
(vs from the community). If a pull request requires a quick turn around, please
explicitly communicate this via [#synapse-dev:matrix.org](https://matrix.to/#/#synapse-dev:matrix.org)
or as a comment on the pull request.

Once an initial review has been completed and the author has made additional changes,
follow-up reviews should go back to the same reviewer. This helps build a shared
context and conversation between author and reviewer.

As a team we aim to keep the number of inflight pull requests to a minimum to ensure
that ongoing work is finished before starting new work.

Performing a review
-------------------

To communicate to the rest of the team the status of each pull request, team
members should do the following:

* Assign themselves to the pull request (they should be left assigned to the
  pull request until it is merged, closed, or are no longer the reviewer);
* Review the pull request by leaving comments, questions, and suggestions;
* Mark the pull request appropriately (as needing changes or accepted).

If you are unsure about a particular part of the pull request (or are not confident
in your understanding of part of the code) then ask questions or request review
from the team again. When requesting review from the team be sure to leave a comment
with the rationale on why you're putting it back in the queue.
