# Building full schema dumps

These schemas need to be made from a database that has had all background updates run.

To do so, use `scripts-dev/make_full_schema.sh`. This will produce
`full.sql.postgres ` and `full.sql.sqlite` files.

Ensure postgres is installed and your user has the ability to run bash commands
such as `createdb`.

```
./scripts-dev/make_full_schema.sh -p postgres_username -o output_dir/
```
