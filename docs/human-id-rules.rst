This document outlines the format for human-readable IDs within matrix.

Overview
--------
UTF-8 is quickly becoming the standard character encoding set on the web. As
such, Matrix requires that all strings MUST be encoded as UTF-8. However,
using Unicode as the character set for human-readable IDs is troublesome. There
are many different characters which appear identical to each other, but would
identify different users. In addition, there are non-printable characters which
cannot be rendered by the end-user. This opens up a security vulnerability with
phishing/spoofing of IDs, commonly known as a homograph attack.

Web browers encountered this problem when International Domain Names were
introduced. A variety of checks were put in place in order to protect users. If
an address failed the check, the raw punycode would be displayed to disambiguate
the address. Similar checks are performed by home servers in Matrix. However, 
Matrix does not use punycode representations, and so does not show raw punycode 
on a failed check. Instead, home servers must outright reject these misleading 
IDs.

Types of human-readable IDs
---------------------------
There are two main human-readable IDs in question:

- Room aliases
- User IDs
 
Room aliases look like ``#localpart:domain``. These aliases point to opaque
non human-readable room IDs. These pointers can change, so there is already an
issue present with the same ID pointing to a different destination at a later
date.

User IDs look like ``@localpart:domain``. These represent actual end-users, and
unlike room aliases, there is no layer of indirection. This presents a much
greater concern with homograph attacks. 

Checks
------
- Similar to web browsers.
- blacklisted chars (e.g. non-printable characters)
- mix of language sets from 'preferred' language not allowed. 
- Language sets from CLDR dataset.
- Treated in segments (localpart, domain)
- Additional restrictions for ease of processing IDs.
   - Room alias localparts MUST NOT have ``#`` or ``:``.
   - User ID localparts MUST NOT have ``@`` or ``:``.

Rejecting
---------
- Home servers MUST reject room aliases which do not pass the check, both on 
  GETs and PUTs.
- Home servers MUST reject user ID localparts which do not pass the check, both
  on creation and on events.
- Any home server whose domain does not pass this check, MUST use their punycode
  domain name instead of the IDN, to prevent other home servers rejecting you.
- Error code is ``M_FAILED_HUMAN_ID_CHECK``. (generic enough for both failing 
  due to homograph attacks, and failing due to including ``:`` s, etc)
- Error message MAY go into further information about which characters were
  rejected and why.
- Error message SHOULD contain a ``failed_keys`` key which contains an array
  of strings which represent the keys which failed the check e.g::
  
    failed_keys: [ user_id, room_alias ]
  
Other considerations
--------------------
- Basic security: Informational key on the event attached by HS to say "unsafe 
  ID". Problem: clients can just ignore it, and since it will appear only very
  rarely, easy to forget when implementing clients.
- Moderate security: Requires client handshake. Forces clients to implement
  a check, else they cannot communicate with the misleading ID. However, this is
  extra overhead in both client implementations and round-trips.
- High security: Outright rejection of the ID at the point of creation / 
  receiving event. Point of creation rejection is preferable to avoid the ID
  entering the system in the first place. However, malicious HSes can just allow
  the ID. Hence, other home servers must reject them if they see them in events.
  Client never sees the problem ID, provided the HS is correctly implemented.
- High security decided; client doesn't need to worry about it, no additional
  protocol complexity aside from rejection of an event.