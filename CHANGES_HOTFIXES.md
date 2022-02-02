Differences between the hotfixes release branch
===============================================

- 2017/05/23: [e5537cf98333b428dbc481ed443daed2f0cfa074](https://github.com/matrix-org/synapse/commit/e5537cf98333b428dbc481ed443daed2f0cfa074) and introduced a `member_limiter` on the
  `RoomMemberHandler`, later tweaked by subsequent commits. This wraps the call to `update_membership_locked` and there looks to be timing-related changes.
- 2017/10/12: [fae708c0e8c35930f1172322b7c0e9f0b1b3f9a4](https://github.com/matrix-org/synapse/commit/fae708c0e8c35930f1172322b7c0e9f0b1b3f9a4) from [matrix-appservice-irc#506](https://github.com/matrix-org/matrix-appservice-irc/issues/506) suppresses the requirement that application services can only lookup joined members if they control a user which is already in this room.
- 2018/02/14: [66dcbf47a36b5ca0e88d4658578d6fb5e6dbd910](https://github.com/matrix-org/synapse/commit/66dcbf47a36b5ca0e88d4658578d6fb5e6dbd910) disables auto search for prefixes in event search.
- 2018/02/14: [8f8ea91eefcc43c5ac24e85b14a86af4da53e6e0](https://github.com/matrix-org/synapse/commit/8f8ea91eefcc43c5ac24e85b14a86af4da53e6e0) bumps client_ip LAST_SEEN_GRANULARITY from 2 to 10 minutes.
- 2018/06/04: [9e38981ae47d03467a954c3c540c51b567f6e50b](https://github.com/matrix-org/synapse/commit/9e38981ae47d03467a954c3c540c51b567f6e50b) and subsequent commits send http pushes directly to a local address, rather than via cloudflare.
- 2022/01/07: [5cc41f1b05416954f4c9e7aea1df308f4a451abe](https://github.com/matrix-org/synapse/commit/5cc41f1b05416954f4c9e7aea1df308f4a451abe) introduces debug logging
