If enabling the 'consent' resource in synapse, you will need some templates
for the HTML to be served to the user. This directory contains very simple
examples of the sort of thing that can be done.

You'll need to add this sort of thing to your homeserver.yaml:

```
form_secret: <unique but arbitrary secret>

user_consent:
  template_dir: docs/privacy_policy_templates
  default_version: 1.0
```

You should then be able to enable the `consent` resource under a `listener`
entry. For example:

```
listeners:
  - port: 8008
    resources:
      - names: [client, consent]
```
