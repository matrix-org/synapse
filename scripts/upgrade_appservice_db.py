from synapse.storage import read_schema
import argparse
import json
import sqlite3


def do_other_deltas(cursor):
    cursor.execute("PRAGMA user_version")
    row = cursor.fetchone()

    if row and row[0]:
        user_version = row[0]
        # Run every version since after the current version.
        for v in range(user_version + 1, 10):
            print "Running delta: %d" % (v,)
            sql_script = read_schema("delta/v%d" % (v,))
            cursor.executescript(sql_script)


def update_app_service_table(cur):
    cur.execute("SELECT id, regex FROM application_services_regex")
    for row in cur.fetchall():
        try:
            print "checking %s..." % row[0]
            json.loads(row[1])
        except ValueError:
            # row isn't in json, make it so.
            string_regex = row[1]
            new_regex = json.dumps({
                "regex": string_regex,
                "exclusive": True
            })
            cur.execute(
                "UPDATE application_services_regex SET regex=? WHERE id=?",
                (new_regex, row[0])
            )


def main(dbname):
    con = sqlite3.connect(dbname)
    cur = con.cursor()
    do_other_deltas(cur)
    update_app_service_table(cur)
    cur.execute("PRAGMA user_version = 14")
    cur.close()
    con.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("database")
    args = parser.parse_args()

    main(args.database)
