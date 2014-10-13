Signing JSON
============

JSON is signed by encoding the JSON object without ``signatures`` or ``meta``
keys using a canonical encoding. The JSON bytes are then signed using the
signature algorithm and the signature encoded using base64 with the padding
stripped. The resulting base64 signature is added to an object under the
*signing key identifier* which is added to the ``signatures`` object under the
name of the server signing it which is added back to the original JSON object
along with the ``meta`` object.

The *signing key identifier* is the concatenation of the *signing algorithm*
and a *key version*. The *signing algorithm* identifies the algorithm used to
sign the JSON. The currently support value for *signing algorithm* is
``ed25519`` as implemented by NACL (http://nacl.cr.yp.to/). The *key version*
is used to distinguish between different signing keys used by the same entity.

The ``meta`` object and the ``signatures`` object are not covered by the
signature. Therefore intermediate servers can add metadata such as time stamps
and additional signatures.


::

  {
     "name": "example.org",
     "signing_keys": {
       "ed25519:1": "XSl0kuyvrXNj6A+7/tkrB9sxSbRi08Of5uRhxOqZtEQ"
     },
     "meta": {
        "retrieved_ts_ms": 922834800000
     },
     "signatures": {
        "example.org": {
           "ed25519:1": "s76RUgajp8w172am0zQb/iPTHsRnb4SkrzGoeCOSFfcBY2V/1c8QfrmdXHpvnc2jK5BD1WiJIxiMW95fMjK7Bw"
        }
     }
  }

::

  def sign_json(json_object, signing_key, signing_name):
      signatures = json_object.pop("signatures", {})
      meta = json_object.pop("meta", None)

      signed = signing_key.sign(encode_canonical_json(json_object))
      signature_base64 = encode_base64(signed.signature)

      key_id = "%s:%s" % (signing_key.alg, signing_key.version)
      signatures.setdefault(sigature_name, {})[key_id] = signature_base64

      json_object["signatures"] = signatures
      if meta is not None:
          json_object["meta"] = meta

      return json_object

Checking for a Signature
------------------------

To check if an entity has signed a JSON object a server does the following

1. Checks if the ``signatures`` object contains an entry with the name of the
   entity. If the entry is missing then the check fails.
2. Removes any *signing key identifiers* from the entry with algorithms it
   doesn't understand. If there are no *signing key identifiers* left then the
   check fails.
3. Looks up *verification keys* for the remaining *signing key identifiers*
   either from a local cache or by consulting a trusted key server. If it
   cannot find a *verification key* then the check fails.
4. Decodes the base64 encoded signature bytes. If base64 decoding fails then
   the check fails.
5. Checks the signature bytes using the *verification key*. If this fails then
   the check fails. Otherwise the check succeeds.

Canonical JSON
--------------

The canonical JSON encoding for a value is the shortest UTF-8 JSON encoding
with dictionary keys lexicographically sorted by unicode codepoint. Numbers in
the JSON value must be integers in the range [-(2**53)+1, (2**53)-1].

::

 import json

 def canonical_json(value):
     return json.dumps(
         value,
         ensure_ascii=False,
         separators=(',',':'),
         sort_keys=True,
     ).encode("UTF-8")

Grammar
+++++++

Adapted from the grammar in http://tools.ietf.org/html/rfc7159 removing
insignificant whitespace, fractions, exponents and redundant character escapes

::

 value     = false / null / true / object / array / number / string
 false     = %x66.61.6c.73.65
 null      = %x6e.75.6c.6c
 true      = %x74.72.75.65
 object    = %x7B [ member *( %x2C member ) ] %7D
 member    = string %x3A value
 array     = %x5B [ value *( %x2C value ) ] %5B
 number    = [ %x2D ] int
 int       = %x30 / ( %x31-39 *digit )
 digit     = %x30-39
 string    = %x22 *char %x22
 char      = unescaped / %x5C escaped
 unescaped = %x20-21 / %x23-5B / %x5D-10FFFF
 escaped   = %x22 ; "    quotation mark  U+0022
           / %x5C ; \    reverse solidus U+005C
           / %x62 ; b    backspace       U+0008
           / %x66 ; f    form feed       U+000C
           / %x6E ; n    line feed       U+000A
           / %x72 ; r    carriage return U+000D
           / %x74 ; t    tab             U+0009
           / %x75.30.30.30 (%x30-37 / %x62 / %x65-66) ; u000X
           / %x75.30.30.31 (%x30-39 / %x61-66)        ; u001X

Signing Events
==============

Signing events is a more complicated process since servers can choose to redact
non-essential event contents. Before signing the event it is encoded as
Canonical JSON and hashed using SHA-256. The resulting hash is then stored
in the event JSON in a ``hash`` object under a ``sha256`` key. Then all
non-essential keys are stripped from the event object, and the resulting object
which included the ``hash`` key is signed using the JSON signing algorithm.

Servers can then transmit the entire event or the event with the non-essential
keys removed. Receiving servers can then check the entire event if it is
present by computing the SHA-256 of the event excluding the ``hash`` object, or
by using the ``hash`` object included in the event if keys have been redacted.

New hash functions can be introduced by adding additional keys to the ``hash``
object. Since the ``hash`` object cannot be redacted a server shouldn't allow
too many hashes to be listed, otherwise a server might embed illict data within
the ``hash`` object. For similar reasons a server shouldn't allow hash values
that are too long.

[[TODO(markjh): We might want to specify a maximum number of keys for the
``hash`` and we might want to specify the maximum output size of a hash]]

[[TODO(markjh) We might want to allow the server to omit the output of well
known hash functions like SHA-256 when none of the keys have been redacted]]
