Matrix Specification NOTHAVEs
=============================

This document contains sections of the main specification that have been
temporarily removed, because they specify intentions or aspirations that have
in no way yet been implemented. Rather than outright-deleting them, they have
been moved here so as to stand as an initial version for such time as they
become extant.


Presence
========

Idle Time
---------
As well as the basic ``presence`` field, the presence information can also show
a sense of an "idle timer". This should be maintained individually by the
user's clients, and the home server can take the highest reported time as that
to report. When a user is offline, the home server can still report when the
user was last seen online.
