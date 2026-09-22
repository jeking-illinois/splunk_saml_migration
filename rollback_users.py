#!/usr/bin/env python3
"""
Undo a sync_users.py --apply run, using the journal it wrote.

    python rollback_users.py --journal user_journal_20260922_101500.jsonl --verify
    python rollback_users.py --journal <file>            # DRY RUN
    python rollback_users.py --journal <file> --apply    # actually restore

The journal records `roles_before` for every user the sync attempted, written
BEFORE the mutation - so it is complete even if the run died partway through, and
it covers users whose write failed as well as users whose write succeeded.

Restoring means one of two things:

    roles_before non-empty   replace the mapping with exactly that list
    roles_before EMPTY       the user had no SAML mapping at all, so the correct
                             restore is to DELETE the mapping, not to write an
                             empty one. This is the normal case for a user the
                             sync CREATED on the target.

A user whose live roles already match `roles_before` is skipped, so this is safe
to re-run.

--verify does no writes: it re-fetches the whole role map and reports, per user,
whether the live state matches `roles_before` (rollback not needed / already
done), `roles_intended` (the sync succeeded and is still in place), or neither.
Run that first - it tells you how much of the sync actually landed.

A bare filename for --journal is looked up in the results dir.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

from clients import ApiError, RestClient
from config import add_common_args, configure
from report import Sheet, banner, token_warning, write_workbook

COLUMNS = [
    ("User", 34), ("Roles Before", 52), ("Roles Intended", 52), ("Roles Live", 52),
    ("Live Matches", 16), ("Action", 14), ("Result", 14), ("Detail", 60),
]


def load_journal(cfg, path):
    """Returns (meta, resolved_path, records). Later records for the same user win."""
    if not os.path.isabs(path):
        candidate = os.path.join(cfg.results_dir, path)
        path = candidate if os.path.exists(candidate) else path
    if not os.path.exists(path):
        print(f"ERROR: journal not found: {path}")
        sys.exit(1)

    meta, by_user = {}, {}
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                # A truncated last line is exactly what a killed run leaves behind.
                # Skip it loudly rather than refusing to roll anything back.
                print(f"  WARNING: {os.path.basename(path)}:{line_no} unparseable, "
                      f"skipped ({e})")
                continue
            if rec.get("_meta"):
                meta = rec
                continue
            if rec.get("user"):
                by_user[rec["user"]] = rec
    return meta, path, [by_user[u] for u in sorted(by_user)]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_args(ap)
    ap.add_argument("--journal", required=True,
                    help="user_journal_*.jsonl from a sync_users.py --apply run "
                         "(bare filename is looked up in the results dir)")
    ap.add_argument("--verify", action="store_true",
                    help="read-only: report live state vs the journal, write nothing")
    ap.add_argument("--users", help="comma-separated usernames to restore instead of all")
    args = ap.parse_args()

    cfg = configure(args)
    meta, journal_path, records = load_journal(cfg, args.journal)

    if args.users:
        wanted = {u.strip() for u in args.users.split(",") if u.strip()}
        records = [r for r in records if r["user"] in wanted]
    if args.limit:
        records = records[:args.limit]

    mode = "VERIFY" if args.verify else ("APPLY" if args.apply else "DRY RUN")
    client = RestClient(cfg, "target")

    banner("USER ROLE ROLLBACK", cfg, mode, [
        f"journal:          {journal_path}",
        f"journal run at:   {meta.get('started_at', '(unknown)')}",
        f"journal source:   {meta.get('source', '(unknown)')}",
        f"journal target:   {meta.get('target', '(unknown)')}",
        f"users in journal: {len(records)}",
        f"  of those, had NO prior mapping (restore = delete): "
        f"{sum(1 for r in records if not r.get('roles_before'))}",
    ])
    token_warning(client, "target")

    # One bulk read instead of a GET per user - the same reason sync_users
    # verifies in bulk. Per-user reads are unstable right after a write, and this
    # is 1 call instead of hundreds.
    print("\n  fetching live SAML-user-role-map ... ", end="", flush=True)
    live = client.user_role_map()
    print(f"{len(live)} users")

    rows, counts = [], {}
    matches = {"roles_before": 0, "roles_intended": 0, "neither": 0, "no_mapping": 0}

    for rec in records:
        user = rec["user"]
        before = set(rec.get("roles_before") or [])
        intended = set(rec.get("roles_intended") or [])
        now = set(live.get(user, []))
        present = user in live

        if not present:
            match = "no mapping"
            matches["no_mapping"] += 1
        elif now == before:
            match = "roles_before"
            matches["roles_before"] += 1
        elif now == intended:
            match = "roles_intended"
            matches["roles_intended"] += 1
        else:
            match = "neither"
            matches["neither"] += 1

        # Where we want to end up, and whether we are already there.
        want_deleted = not before
        at_rest = (not present) if want_deleted else (now == before)

        action = "none" if at_rest else ("delete" if want_deleted else "restore")
        result, detail = "already-ok", ""

        if at_rest:
            result = "already-ok"
        elif args.verify:
            result, detail = "would-" + action, "verify only"
        elif not args.apply:
            result, detail = "dry-run", f"would {action}"
        else:
            try:
                if want_deleted:
                    client.delete_user(user)
                    result, detail = "deleted", "mapping removed (had none before)"
                else:
                    ok, detail, _ = client.replace_user_roles(
                        user, sorted(before), exists=present)
                    result = "restored" if ok else "error"
            except ApiError as e:
                # A delete of something already gone is the desired end state.
                if want_deleted and e.status in (400, 404):
                    result, detail = "already-ok", "no mapping to remove"
                else:
                    result, detail = "error", f"{e.status} {e.message}"
            time.sleep(cfg.sleep)

        counts[result] = counts.get(result, 0) + 1
        rows.append({
            "User": user,
            "Roles Before": sorted(before),
            "Roles Intended": sorted(intended),
            "Roles Live": sorted(now),
            "Live Matches": match,
            "Action": action,
            "Result": result,
            "Detail": detail,
        })

        if result == "error":
            print(f"  FAIL {user:<34} {detail[:80]}")
        elif result in ("restored", "deleted"):
            done = counts.get("restored", 0) + counts.get("deleted", 0)
            if done <= 3 or done % 50 == 0:
                print(f"  [{done:4d}/{len(records)}] {user[:40]:<40} {result}")

    print("\n  Live state vs journal:")
    for k, v in matches.items():
        print(f"    {k:<16} {v}")

    summary = [
        ("Mode", mode),
        ("Run at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Config", cfg.path),
        ("Target stack", cfg.target.label),
        ("Target credential", cfg.target.token_source),
        ("Journal", journal_path),
        ("Journal run at", meta.get("started_at", "")),
        ("Journal source stack", meta.get("source", "")),
        ("Journal source roles", meta.get("source_roles", "")),
        ("", ""),
        ("Users in journal", len(records)),
        ("  had no prior mapping (restore = delete)",
         sum(1 for r in records if not r.get("roles_before"))),
        ("", ""),
        ("Live state vs journal:", ""),
    ]
    summary += [(f"  live == {k}" if k != "no_mapping" else "  no live mapping", v)
                for k, v in matches.items()]
    summary += [("", ""), ("Results:", "")]
    summary += [(f"  {k}", v) for k, v in sorted(counts.items())]

    out = cfg.results_path(args.out or "user_rollback.xlsx")
    write_workbook(out, Sheet("Rollback", COLUMNS, rows, colour_by="Result"),
                   summary=summary)

    print(f"\n{'=' * 74}")
    print("SUMMARY")
    print(f"{'=' * 74}")
    for k, v in sorted(counts.items()):
        print(f"  {k:<14} {v}")
    if args.verify:
        print("\n  VERIFY - nothing was written.")
    elif not args.apply:
        print("\n  DRY RUN - nothing was written. Re-run with --apply to restore.")
    print(f"  Excel report: {out}")


if __name__ == "__main__":
    main()
