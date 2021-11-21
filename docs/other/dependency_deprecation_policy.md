Deprecation Policy for Platform Dependencies
============================================

Synapse has a number of platform dependencies, including Python and PostgreSQL.
This document outlines the policy towards which versions we support, and when we
drop support for versions in the future.


Policy
------

Synapse follows the upstream support life cycles for Python and PostgreSQL,
i.e. when a version reaches End of Life Synapse will withdraw support for that
version in future releases.

Details on the upstream support life cycles for Python and PostgreSQL are
documented at https://endoflife.date/python and
https://endoflife.date/postgresql.


Context
-------

It is important for system admins to have a clear understanding of the platform
requirements of Synapse and its deprecation policies so that they can
effectively plan upgrading their infrastructure ahead of time. This is
especially important in contexts where upgrading the infrastructure requires
auditing and approval from a security team, or where otherwise upgrading is a
long process.

By following the upstream support life cycles Synapse can ensure that its
dependencies continue to get security patches, while not requiring system admins
to constantly update their platform dependencies to the latest versions.
