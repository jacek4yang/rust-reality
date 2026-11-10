#!/usr/bin/env python3
"""Select the exact-head GitHub Actions run Frozen should bind.

`gh run list --commit SHA` returns newest first. Duplicate PR events often
leave a cancelled twin beside a successful run (for example #469 CI
42369741781 and 42369741687). Taking `--limit 1` and requiring that row
to be success fails closed when the newest row is cancelled, and would
also fail after PR-scoped concurrency cancellation.

Policy:
- Ignore runs whose headSha does not match, are not completed, or are cancelled.
- Among the rest, take the newest (first remaining row).
- That run must have concluded success. A later failure is not replaced by
  an older success.
- Missing, only-cancelled, or unsuccessful latest completed work is an error.

This script never treats cancelled, skipped, or in-progress runs as success.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def select_run(runs: list[dict[str, Any]], head_sha: str) -> int:
    if not head_sha:
        raise SystemExit("exact-head SHA is missing")
    eligible = [
        run
        for run in runs
        if run.get("headSha") == head_sha
        and run.get("status") == "completed"
        and run.get("conclusion") != "cancelled"
    ]
    if not eligible:
        raise SystemExit(
            "Exact-head required workflow is missing or only cancelled"
        )
    latest = eligible[0]
    conclusion = latest.get("conclusion")
    if conclusion != "success":
        raise SystemExit(
            f"Latest exact-head required workflow is {conclusion}"
        )
    run_id = latest.get("databaseId")
    if not isinstance(run_id, int):
        raise SystemExit("Latest exact-head required workflow has no databaseId")
    return run_id


def _self_test() -> None:
    sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    def run(**kwargs: Any) -> dict[str, Any]:
        row = {
            "headSha": sha,
            "status": "completed",
            "conclusion": "success",
            "databaseId": 1,
        }
        row.update(kwargs)
        return row

    # Newest success.
    assert select_run([run(databaseId=20), run(databaseId=10)], sha) == 20

    # Cancelled twin is ignored; older success is used.
    assert (
        select_run(
            [
                run(databaseId=22, conclusion="cancelled"),
                run(databaseId=21),
            ],
            sha,
        )
        == 21
    )

    # A later failure is not hidden by an older success.
    try:
        select_run(
            [
                run(databaseId=32, conclusion="failure"),
                run(databaseId=31),
            ],
            sha,
        )
    except SystemExit as error:
        assert "failure" in str(error)
    else:
        raise SystemExit("expected later failure to be rejected")

    # Only cancelled / empty / wrong SHA / in-progress.
    for runs in (
        [run(conclusion="cancelled")],
        [],
        [run(headSha=other)],
        [run(status="in_progress", conclusion=None)],
    ):
        try:
            select_run(runs, sha)
        except SystemExit:
            pass
        else:
            raise SystemExit(f"expected rejection for {runs!r}")

    # In-progress newest does not block an older completed success.
    assert (
        select_run(
            [
                run(databaseId=41, status="in_progress", conclusion=None),
                run(databaseId=40),
            ],
            sha,
        )
        == 40
    )

    print("select_exact_head_run self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--head-sha")
    parser.add_argument("--runs-json")
    args = parser.parse_args()
    if args.self_test:
        _self_test()
        return
    if not args.head_sha or not args.runs_json:
        raise SystemExit("usage: select_exact_head_run.py --head-sha SHA --runs-json PATH")
    with open(args.runs_json, encoding="utf-8") as handle:
        runs = json.load(handle)
    if not isinstance(runs, list):
        raise SystemExit("runs JSON must be a list")
    print(select_run(runs, args.head_sha))


if __name__ == "__main__":
    main()
