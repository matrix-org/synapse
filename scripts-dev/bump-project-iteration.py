import argparse
import datetime
import json
import sys
import subprocess
import logging

from typing import Dict, Any, Sequence, Tuple, List

logger = logging.getLogger(__name__)


def execute_query(query: str) -> Dict[str, Any]:
    stdout = subprocess.check_output(
        [
            "gh",
            "api",
            "graphql",
            "-f",
            "query=" + query
        ]
    )
    logger.debug("QUERY: %s", query)
    result = json.loads(stdout)
    logger.debug("RESULT: %s", result)
    return result


def execute_query_paginate(query: str) -> List[Dict[str, Any]]:
    results = []

    logger.debug("PAGINATED QUERY: %s", query)
    args = [
        "gh",
        "api",
        "graphql",
        "--paginate",
        "-f", "query=" + query,
        # Use --jq to force each pagination to land on a new line, c.f.
        # https://github.com/cli/cli/issues/1268#issuecomment-1261505503
        "--jq", ".",
    ]
    stdout = subprocess.check_output(args)
    for i, line in enumerate(stdout.splitlines()):
        if line:
            result = json.loads(line)
            logger.debug("RESULT %i: %s", i, result)
            results.append(result)
    return results


SYNAPSE_PROJECT_ID = "PVT_kwDOAIB0Bs4ABmip"


def determine_iteration_ids() -> Tuple[str, str]:
    result = execute_query(
        """
        {
          node(id: "%s") {
            ... on ProjectV2 {
              field(name:"Week") {
                ... on ProjectV2IterationField {
                  configuration {
                    completedIterations {
                      id
                      title
                      startDate
                      duration
                    }
                    iterations {
                      id
                      title
                      startDate
                      duration
                    }
                  }
                }
              }
            }
          }
        }
    """
        % (SYNAPSE_PROJECT_ID,)
    )

    config = result["data"]["node"]["field"]["configuration"]
    completed = config["completedIterations"]
    previous = max(completed, key=lambda d: datetime.date.fromisoformat(d["startDate"]))

    outstanding = config["iterations"]
    current = min(
        outstanding, key=lambda d: datetime.date.fromisoformat(d["startDate"])
    )

    logger.info(
        "Previous iteration: %s (%s) starting, %s ending %s",
        previous["id"],
        previous["title"],
        previous["startDate"],
        datetime.date.fromisoformat(previous["startDate"])
        + datetime.timedelta(days=previous["duration"]),
    )
    logger.info(
        "Current iteration:  %s (%s) starting, %s ending %s",
        current["id"],
        current["title"],
        current["startDate"],
        datetime.date.fromisoformat(current["startDate"])
        + datetime.timedelta(days=current["duration"]),
    )

    return previous["id"], current["id"]


def fetch_outstanding_items(previous_iteration: str) -> List[str]:
    results = execute_query_paginate(
        """
        query($endCursor: String) {
          node(id: "%s") {
            ... on ProjectV2 {
              items (first: 50, after: $endCursor) {
                nodes {
                  id
                  fieldValueByName(name: "Week") {
                    ... on ProjectV2ItemFieldIterationValue {
                      iterationId
                    }
                  }
                }
                pageInfo {
                  hasNextPage
                  endCursor
                }
              }
            }
          }
        }
        """
        % (SYNAPSE_PROJECT_ID,)
    )
    outstanding = []
    for result in results:
        for node in result["data"]["node"]["items"]["nodes"]:
            if (node["fieldValueByName"] or {}).get("iterationId") == previous_iteration:
                outstanding.append(node["id"])
    return outstanding


def main(argv: Sequence[str]) -> int:
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    previous_iter, current_iter = determine_iteration_ids()
    outstanding = fetch_outstanding_items(previous_iter)

    for item_id in outstanding:
        print(item_id)

    # TODO: filter out the items which are archived or status: done
    # TODO: print out the remaining items' titles, assignee, repo, issue/PR number, status column
    # TODO: prompt user to confirm moving those from week A to week B
    # TODO: do the moves

    return 0


parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
