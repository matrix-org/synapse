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

  def sign_json(value, signing_key, signing_name):
      signatures = value.pop("signatures", {})
      signatures_for_name = signatures.pop(signing_name, {})
      meta = value.pop("meta", None)
      signature = signing_key.sign(canonical_json(value))
      key_identifier = "%s:%s" % (signing_key.algorithm, signing_key.version)
      signatures_for_name[key_identifier] = encode_base64(signature.signature)
      signatures[signing_name] = signatures_for_name
      value["signatures"] = signatures
      if meta is not None:
          value["meta"] = meta
      return value

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
