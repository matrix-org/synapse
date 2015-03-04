import json
import logging

logger = logging.getLogger(__name__)


def run_upgrade(cur):
    cur.execute("SELECT id, regex FROM application_services_regex")
    for row in cur.fetchall():
        try:
            logger.debug("Checking %s..." % row[0])
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
