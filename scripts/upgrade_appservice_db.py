import argparse
import json
import sqlite3


def main(dbname):
    con = sqlite3.connect(dbname)
    cur = con.cursor()
    cur.execute("SELECT id, regex FROM application_services_regex")
    for row in cur.fetchall():
        try:
            print "checking %s..." % row[0]
            json.loads(row[1])
            print "Already in new format"
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
    cur.close()
    con.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("database")
    args = parser.parse_args()

    main(args.database)
