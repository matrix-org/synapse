In C-S API > Registration/Login:

Captcha-based
~~~~~~~~~~~~~
:Type: 
  ``m.login.recaptcha``
:Description: 
  Login is supported by responding to a captcha, in this case Google's 
  Recaptcha.

To respond to this type, reply with::

  {
    "type": "m.login.recaptcha",
    "challenge": "<challenge token>",
    "response": "<user-entered text>"
  }

The Recaptcha parameters can be obtained in Javascript by calling::

  Recaptcha.get_challenge();
  Recaptcha.get_response();

The home server MUST respond with either new credentials, the next stage of the
login process, or a standard error response.




In Events:

Common event fields
-------------------
All events MUST have the following fields:

``event_id``
  Type:
    String.
  Description:
    Represents the globally unique ID for this event.

``type``
  Type:
    String.
  Description:
    Contains the event type, e.g. ``m.room.message``

``content``
  Type:
    JSON Object.
  Description:
    Contains the content of the event. When interacting with the REST API, this is the HTTP body.

``room_id``
  Type:
    String.
  Description:
    Contains the ID of the room associated with this event.

``user_id``
  Type:
    String.
  Description:
    Contains the fully-qualified ID of the user who *sent* this event.

State events have the additional fields:

``state_key``
  Type:
    String.
  Description:
    Contains the state key for this state event. If there is no state key for this state event, this
    will be an empty string. The presence of ``state_key`` makes this event a state event.

``required_power_level``
  Type:
    Integer.
  Description:
    Contains the minimum power level a user must have before they can update this event.

``prev_content``
  Type:
    JSON Object.
  Description:
    Optional. Contains the previous ``content`` for this event. If there is no previous content, this
    key will be missing.
    
.. TODO-spec
  How do "age" and "ts" fit in to all this? Which do we expose?
