Stabilize [MSC3231](https://github.com/matrix-org/matrix-doc/pull/3231).

Client implementations using `m.login.registration_token` should switch to the stable identifiers:
* `org.matrix.msc3231.login.registration_token` in query parameters and request/response bodies becomes `m.login.registration_token`.
* `/_matrix/client/unstable/org.matrix.msc3231/register/org.matrix.msc3231.login.registration_token/validity` becomes `/_matrix/client/v1/register/m.login.registration_token/validity`.