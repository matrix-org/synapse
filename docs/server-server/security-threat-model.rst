Overview
========

Scope
-----

This document considers threats specific to the server to server federation 
synapse protocol.


Attacker
--------

It is assumed that the attacker can see and manipulate all network traffic 
between any of the servers and may be in control of one or more homeservers 
participating in the federation protocol.

Threat Model
============

Denial of Service
-----------------

The attacker could attempt to prevent delivery of messages to or from the 
victim in order to:

    * Disrupt service or marketing campaign of a commercial competitor.
    * Censor a discussion or censor a participant in a discussion.
    * Perform general vandalism.

Threat: Resource Exhaustion
~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could cause the victims server to exhaust a particular resource 
(e.g. open TCP connections, CPU, memory, disk storage)

Threat: Unrecoverable Consistency Violations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could send messages which created an unrecoverable "split-brain"
state in the cluster such that the victim's servers could no longer dervive a
consistent view of the chatroom state.

Threat: Bad History
~~~~~~~~~~~~~~~~~~~

An attacker could convince the victim to accept invalid messages which the 
victim would then include in their view of the chatroom history. Other servers
in the chatroom would reject the invalid messages and potentially reject the
victims messages as well since they depended on the invalid messages.

Threat: Block Network Traffic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could try to firewall traffic between the victim's server and some
or all of the other servers in the chatroom.

Threat: High Volume of Messages
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could send large volumes of messages to a chatroom with the victim
making the chatroom unusable.

Threat: Banning users without necessary authorisation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could attempt to ban a user from a chatroom with the necessary
authorisation.

Spoofing
--------

An attacker could try to send a message claiming to be from the victim without 
the victim having sent the message in order to:

    * Impersonate the victim while performing illict activity.
    * Obtain privileges of the victim.

Threat: Altering Message Contents
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could try to alter the contents of an existing message from the 
victim.

Threat: Fake Message "origin" Field
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could try to send a new message purporting to be from the victim
with a phony "origin" field.

Spamming
--------

The attacker could try to send a high volume of solicicted or unsolicted 
messages to the victim in order to:
    
    * Find victims for scams.
    * Market unwanted products.

Threat: Unsoliticted Messages
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could try to send messages to victims who do not wish to receive 
them.

Threat: Abusive Messages
~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could send abusive or threatening messages to the victim

Spying
------

The attacker could try to access message contents or metadata for messages sent
by the victim or to the victim that were not intended to reach the attacker in
order to:

    * Gain sensitive personal or commercial information.
    * Impersonate the victim using credentials contained in the messages.
      (e.g. password reset messages)
    * Discover who the victim was talking to and when.

Threat: Disclosure during Transmission
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could try to expose the message contents or metadata during 
transmission between the servers.

Threat: Disclosure to Servers Outside Chatroom
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could try to convince servers within a chatroom to send messages to
a server it controls that was not authorised to be within the chatroom.

Threat: Disclosure to Servers Within Chatroom
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could take control of a server within a chatroom to expose message
contents or metadata for messages in that room.


