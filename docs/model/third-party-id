======================
Third Party Identities
======================

A description of how email addresses, mobile phone numbers and other third
party identifiers can be used to authenticate and discover users in Matrix.


Overview
========

New users need to authenticate their account. An email or SMS text message can 
be a convenient form of authentication. Users already have email addresses 
and phone numbers for contacts in their address book. They want to communicate
with those contacts in Matrix without manually exchanging a Matrix User ID with 
them.

Third Party IDs
---------------

[[TODO(markjh): Describe the format of a 3PID]]


Third Party ID Associations
---------------------------

An Associaton is a binding between a Matrix User ID and a Third Party ID (3PID).
Each 3PID can be associated with one Matrix User ID at a time.

[[TODO(markjh): JSON format of the association.]]

Verification 
------------

An Assocation must be verified by a trusted Verification Server. Email 
addresses and phone numbers can be verified by sending a token to the address 
which a client can supply to the verifier to confirm ownership.

An email Verification Server may be capable of verifying all email 3PIDs or may
be restricted to verifying addresses for a particular domain. A phone number
Verification Server may be capable of verifying all phone numbers or may be
restricted to verifying numbers for a given country or phone prefix.

Verification Servers fulfil a similar role to Certificate Authorities in PKI so
a similar level of vetting should be required before clients trust their
signatures.

A Verification Server may wish to check for existing Associations for a 3PID 
before creating a new Association.

Discovery
---------

Users can discover Associations using a trusted Identity Server. Each 
Association will be signed by the Identity Server. An Identity Server may store
the entire space of Associations or may delegate to other Identity Servers when
looking up Associations.

Each Association returned from an Identity Server must be signed by a 
Verification Server. Clients should check these signatures.

Identity Servers fulfil a similar role to DNS servers.

Privacy
-------

A User may publish the association between their phone number and Matrix User ID
on the Identity Server without publishing the number in their Profile hosted on
their Home Server.

Identity Servers should refrain from publishing reverse mappings and should 
take steps, such as rate limiting, to prevent attackers enumerating the space of
mappings.

Federation
==========

Delegation
----------

Verification Servers could delegate signing to another server by issuing 
certificate to that server allowing it to verify and sign a subset of 3PID on 
its behalf. It would be necessary to provide a language for describing which
subset of 3PIDs that server had authority to validate. Alternatively it could 
delegate the verification step to another server but sign the resulting
association itself.

The 3PID space will have a heirachical structure like DNS so Identity Servers
can delegate lookups to other servers. An Identity Server should be prepared 
to host or delegate any valid association within the subset of the 3PIDs it is 
resonsible for.

Multiple Root Verification Servers
----------------------------------

There can be multiple root Verification Servers and an Association could be
signed by multiple servers if different clients trust different subsets of
the verification servers.

Multiple Root Identity Servers
------------------------------

There can be be multiple root Identity Servers. Clients will add each
Association to all root Identity Servers.

[[TODO(markjh): Describe how clients find the list of root Identity Servers]]


