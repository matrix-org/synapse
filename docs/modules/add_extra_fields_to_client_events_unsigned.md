# Add extra fields to client events unsigned section callbacks

_First introduced in Synapse v1.96.0_

This callback allows modules to add extra fields to the unsigned section of
events when they get sent down to clients.

These get called *every* time an event is to be sent to clients, so care should
be taken to ensure with respect to performance.

### API

To register the callback, use
`register_add_extra_fields_to_unsigned_client_event_callbacks` on the
`ModuleApi`.

The callback should be of the form

```python
async def add_field_to_unsigned(
    event: EventBase,
) -> JsonDict:
```

where the extra fields to add to the event's unsigned section is returned.
(Modules must not attempt to modify the `event` directly).

This cannot be used to alter the "core" fields in the unsigned section emitted
by Synapse itself.

If multiple such callbacks try to add the same field to an event's unsigned
section, the last-registered callback wins.
