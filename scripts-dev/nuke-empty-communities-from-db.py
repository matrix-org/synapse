#!/usr/bin/env python3

import sqlite3
from getopt import getopt
from sys import argv

import psycopg2

if len(argv) < 3 or (argv[1] != "sqlite" and argv[1] != "postgresql"):
    print("Usage:")
    print("    " + argv[0] + " sqlite <path_to_db_file>")
    print("or")
    print(
        "    "
        + argv[0]
        + " postgresql <dbname> [-u <user>] [-p <password>] [-h <host>]"
    )
    quit()

db = None
if argv[1] == "sqlite":
    print("Connecting to SQLite: " + argv[2])
    db = sqlite3.connect(argv[2])
elif argv[1] == "postgresql":
    db_args = "dbname=" + argv[2]
    optlist = getopt(argv[3:], "u:p:h:")
    for opt, arg in optlist[0]:
        if opt == "-u":
            db_args += " user=" + arg
        elif opt == "-p":
            db_args += " password=" + arg
        elif opt == "-h":
            db_args += " host=" + arg
    print("Connecting to PostgreSQL: " + db_args)
    db = psycopg2.connect(db_args)
else:
    print("This should be unreachable, report a bug.")
    quit()

if not db:
    print("Connecting failed")
    quit()

with db:
    cur = db.cursor()
    cur.execute(
        "SELECT g.group_id FROM groups g WHERE (SELECT count(*) "
        "from group_users u WHERE g.group_id = u.group_id) = 0;"
    )
    groups = cur.fetchall()
    for group in groups:
        group_id = group[0]
        print("Deleting " + group_id)
        # group_users should be empty. The first statement is here to avoid a race
        # condition when an empty public community is joined while this script is running.
        cur.execute("DELETE FROM group_users WHERE group_id = '" + group_id + "';")
        cur.execute("DELETE FROM group_invites WHERE group_id = '" + group_id + "';")
        cur.execute("DELETE FROM group_rooms WHERE group_id = '" + group_id + "';")
        cur.execute(
            "DELETE FROM group_summary_rooms WHERE group_id = '" + group_id + "';"
        )
        cur.execute(
            "DELETE FROM group_summary_room_categories WHERE group_id = '"
            + group_id
            + "';"
        )
        cur.execute(
            "DELETE FROM group_room_categories WHERE group_id = '" + group_id + "';"
        )
        cur.execute(
            "DELETE FROM group_summary_users WHERE group_id = '" + group_id + "';"
        )
        cur.execute(
            "DELETE FROM group_summary_roles WHERE group_id = '" + group_id + "';"
        )
        cur.execute("DELETE FROM group_roles WHERE group_id = '" + group_id + "';")
        cur.execute(
            "DELETE FROM group_attestations_renewals WHERE group_id = '"
            + group_id
            + "';"
        )
        cur.execute(
            "DELETE FROM group_attestations_remote WHERE group_id = '" + group_id + "';"
        )
        cur.execute(
            "DELETE FROM local_group_membership WHERE group_id = '" + group_id + "';"
        )
        cur.execute(
            "DELETE FROM local_group_updates WHERE group_id = '" + group_id + "';"
        )
        cur.execute("DELETE FROM groups WHERE group_id = '" + group_id + "';")
    db.commit()
