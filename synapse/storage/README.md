Storage Layer
=============

The storage layer is split up into multiple parts to allow Synapse to run
against different configurations of databases (e.g. single or multiple
databases). The `data_stores` are classes that talk directly to a single
database and have associated schemas, background updates, etc. On top of those
there are (or will be) classes that provide high level interfaces that combine
calls to multiple `data_stores`.

There are also schemas that get applied to every database, regardless of the
data stores associated with them (e.g. the schema version tables), which are
stored in `synapse.storage.schema`.
