========
Profiles
========

A description of Synapse user profile metadata support.


Overview
========

Internally within Synapse users are referred to by an opaque ID, which consists
of some opaque localpart combined with the domain name of their home server.
Obviously this does not yield a very nice user experience; users would like to
see readable names for other users that are in some way meaningful to them.
Additionally, users like to be able to publish "profile" details to inform other
users of other information about them.

It is also conceivable that since we are attempting to provide a
worldwide-applicable messaging system, that users may wish to present different
subsets of information in their profile to different other people, from a
privacy and permissions perspective.

A Profile consists of a display name, an (optional?) avatar picture, and a set
of other metadata fields that the user may wish to publish (email address, phone
numbers, website URLs, etc...). We put no requirements on the display name other
than it being a valid Unicode string. Since it is likely that users will end up
having multiple accounts (perhaps by necessity of being hosted in multiple
places, perhaps by choice of wanting multiple distinct identifies), it would be
useful that a metadata field type exists that can refer to another Synapse User
ID, so that clients and HSes can make use of this information.

Metadata Fields
---------------

[[TODO(paul): Likely this list is incomplete; more fields can be defined as we
think of them. At the very least, any sort of supported ID for the 3rd Party ID
servers should be accounted for here.]]

 * Synapse Directory Server username(s)

 * Email address

 * Phone number - classify "home"/"work"/"mobile"/custom?
 
 * Twitter/Facebook/Google+/... social networks

 * Location - keep this deliberately vague to allow people to choose how
     granular it is
 
 * "Bio" information - date of birth, etc...

 * Synapse User ID of another account

 * Web URL

 * Freeform description text


Visibility Permissions
======================

A home server implementation could offer the ability to set permissions on
limited visibility of those fields. When another user requests access to the
target user's profile, their own identity should form part of that request. The
HS implementation can then decide which fields to make available to the
requestor.

A particular detail of implementation could allow the user to create one or more
ACLs; where each list is granted permission to see a given set of non-public
fields (compare to Google+ Circles) and contains a set of other people allowed
to use it. By giving these ACLs strong identities within the HS, they can be
referenced in communications with it, granting other users who encounter these
the "ACL Token" to use the details in that ACL.

If we further allow an ACL Token to be present on Room join requests or stored
by 3PID servers, then users of these ACLs gain the extra convenience of not
having to manually curate people in the access list; anyone in the room or with
knowledge of the 3rd Party ID is automatically granted access. Every HS and
client implementation would have to be aware of the existence of these ACL
Token, and include them in requests if present, but not every HS implementation
needs to actually provide the full permissions model. This can be used as a
distinguishing feature among competing implementations. However, servers MUST
NOT serve profile information from a cache if there is a chance that its limited
understanding could lead to information leakage.


Client Concerns of Multiple Accounts
====================================

Because a given person may want to have multiple Synapse User accounts, client
implementations should allow the use of multiple accounts simultaneously
(especially in the field of mobile phone clients, which generally don't support
running distinct instances of the same application). Where features like address
books, presence lists or rooms are presented, the client UI should remember to
make distinct with user account is in use for each.


Directory Servers
=================

Directory Servers can provide a forward mapping from human-readable names to
User IDs. These can provide a service similar to giving domain-namespaced names
for Rooms; in this case they can provide a way for a user to reference their
User ID in some external form (e.g. that can be printed on a business card).

The format for Synapse user name will consist of a localpart specific to the
directory server, and the domain name of that directory server:

  @localname:some.domain.name

The localname is separated from the domain name using a colon, so as to ensure
the localname can still contain periods, as users may want this for similarity
to email addresses or the like, which typically can contain them. The format is
also visually quite distinct from email addresses, phone numbers, etc... so
hopefully reasonably "self-describing" when written on e.g. a business card
without surrounding context.

[[TODO(paul): we might have to think about this one - too close to email?
  Twitter? Also it suggests a format scheme for room names of
  #localname:domain.name, which I quite like]]

Directory server administrators should be able to make some kind of policy
decision on how these are allocated. Servers within some "closed" domain (such
as company-specific ones) may wish to verify the validity of a mapping using
their own internal mechanisms; "public" naming servers can operate on a FCFS
basis. There are overlapping concerns here with the idea of the 3rd party
identity servers as well, though in this specific case we are creating a new
namespace to allocate names into.

It would also be nice from a user experience perspective if the profile that a
given name links to can also declare that name as part of its metadata.
Furthermore as a security and consistency perspective it would be nice if each
end (the directory server and the user's home server) check the validity of the
mapping in some way. This needs investigation from a security perspective to
ensure against spoofing.

One such model may be that the user starts by declaring their intent to use a
given user name link to their home server, which then contacts the directory
service. At some point later (maybe immediately for "public open FCFS servers",
maybe after some kind of human intervention for verification) the DS decides to
honour this link, and includes it in its served output. It should also tell the
HS of this fact, so that the HS can present this as fact when requested for the
profile information. For efficiency, it may further wish to provide the HS with
a cryptographically-signed certificate as proof, so the HS serving the profile
can provide that too when asked, avoiding requesting HSes from constantly having
to contact the DS to verify this mapping. (Note: This is similar to the security
model often applied in DNS to verify PTR <-> A bidirectional mappings).


Identity Servers
================

The identity servers should support the concept of pointing a 3PID being able to
store an ACL Token as well as the main User ID. It is however, beyond scope to
do any kind of verification that any third-party IDs that the profile is
claiming match up to the 3PID mappings.


User Interface and Expectations Concerns
========================================

Given the weak "security" of some parts of this model as compared to what users
might expect, some care should be taken on how it is presented to users,
specifically in the naming or other wording of user interface components.

Most notably mere knowledge of an ACL Pointer is enough to read the information
stored in it. It is possible that Home or Identity Servers could leak this
information, allowing others to see it. This is a security-vs-convenience
balancing choice on behalf of the user who would choose, or not, to make use of
such a feature to publish their information.

Additionally, unless some form of strong end-to-end user-based encryption is
used, a user of ACLs for information privacy has to trust other home servers not
to lie about the identify of the user requesting access to the Profile.


API Requirements
================

The data model presented here puts the following requirements on the APIs:

Client-Server
-------------

Requests that a client can make to its Home Server

 * get/set my Display Name
   This should return/take a simple "text/plain" field

 * get/set my Avatar URL
   The avatar image data itself is not stored by this API; we'll just store a
   URL to let the clients fetch it. Optionally HSes could integrate this with
   their generic content attacmhent storage service, allowing a user to set
   upload their profile Avatar and update the URL to point to it.

 * get/add/remove my metadata fields
   Also we need to actually define types of metadata

 * get another user's Display Name / Avatar / metadata fields

[[TODO(paul): At some later stage we should consider the API for:

 * get/set ACL permissions on my metadata fields

 * manage my ACL tokens
]]

Server-Server
-------------

Requests that Home Servers make to others

 * get a user's Display Name / Avatar

 * get a user's full profile - name/avatar + MD fields
   This request must allow for specifying the User ID of the requesting user,
   for permissions purposes. It also needs to take into account any ACL Tokens
   the requestor has.

 * push a change of Display Name to observers (overlaps with the presence API)

Room Event PDU Types
--------------------

Events that are pushed from Home Servers to other Home Servers or clients.

 * user Display Name change
 
 * user Avatar change
   [[TODO(paul): should the avatar image itself be stored in all the room
   histories? maybe this event should just be a hint to clients that they should
   re-fetch the avatar image]]
