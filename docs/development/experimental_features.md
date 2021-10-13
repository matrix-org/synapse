# Implementing experimental features in Synapse

It can be desirable to implement "experimental" features which are disabled by
default and must be explicitly enabled via the Synapse configuration. This is
applicable for features which:

* Are unstable in the Matrix spec (e.g. those defined by an MSC that has not yet been merged).
* Developers are not confident in their use by general Synapse administrators/users
  (e.g. a feature is incomplete, buggy, performs poorly, or needs further testing).

Note that this only really applies to features which are expected to be desirable
to a broad audience. The [module infrastructure](../modules/index.md) should
instead be investigated for non-standard features.

Guarding experimental features behind configuration flags should help with some
of the following scenarios:

* Ensure that clients do not assume that unstable features exist (failing
  gracefully if they do not).
* Unstable features do not become de-facto standards and can be removed
  aggressively (since only those who have opted-in will be affected).
* Ease finding the implementation of unstable features in Synapse (for future
  removal or stabilization).
* Ease testing a feature (or removal of feature) due to enabling/disabling without
  code changes. It also becomes possible to ask for wider testing, if desired.

Experimental configuration flags should be disabled by default (requiring Synapse
administrators to explicitly opt-in), although there are situations where it makes
sense (from a product point-of-view) to enable features by default. This is
expected and not an issue.

It is not a requirement for experimental features to be behind a configuration flag,
but one should be used if unsure.

New experimental configuration flags should be added under the `experimental`
configuration key (see the `synapse.config.experimental` file) and either explain
(briefly) what is being enabled, or include the MSC number.
