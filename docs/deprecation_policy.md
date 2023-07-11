Deprecation Policy for Platform Dependencies
============================================

Synapse has a number of platform dependencies, including Python, Rust, 
PostgreSQL and SQLite. This document outlines the policy towards which versions 
we support, and when we drop support for versions in the future.


Policy
------

Synapse follows the upstream support life cycles for Python and PostgreSQL,
i.e. when a version reaches End of Life Synapse will withdraw support for that
version in future releases.

Details on the upstream support life cycles for Python and PostgreSQL are
documented at [https://endoflife.date/python](https://endoflife.date/python) and
[https://endoflife.date/postgresql](https://endoflife.date/postgresql).

A Rust compiler is required to build Synapse from source. For any given release
the minimum required version may be bumped up to a recent Rust version, and so
people building from source should ensure they can fetch recent versions of Rust
(e.g. by using [rustup](https://rustup.rs/)).

The oldest supported version of SQLite is the version
[provided](https://packages.debian.org/bullseye/libsqlite3-0) by
[Debian oldstable](https://wiki.debian.org/DebianOldStable).

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

For Rust, the situation is a bit different given that a) the Rust foundation
does not generally support older Rust versions, and b) the library ecosystem
generally bump their minimum support Rust versions frequently. In general, the
Synapse team will try to avoid updating the dependency on Rust to the absolute
latest version, but introducing a formal policy is hard given the constraints of
the ecosystem.

On a similar note, SQLite does not generally have a concept of "supported 
release"; bugfixes are published for the latest minor release only. We chose to
track Debian's oldstable as this is relatively conservative, predictably updated
and is consistent with the `.deb` packages released by Matrix.org.