#!/usr/bin/env python3
"""
Copy SAML group -> role mappings from the source stack to the target stack.

    python fetch.py                        # snapshot both stacks first
    python sync_saml_groups.py             # DRY RUN - reports, writes nothing
    python sync_saml_groups.py --apply     # write via /services/admin/SAML-groups

Run this after sync_roles.py and before sync_users.py. Group mappings grant roles
to everyone in the group without touching any per-user mapping, so syncing them
first means sync_users.py can see those roles as already granted and skip a write
it does not need.

For each group in the source snapshot:
  - not on the target                -> POST /services/admin/SAML-groups
  - on the target, roles all present  -> in_sync, no call made
  - on the target, roles missing      -> POST /services/admin/SAML-groups/{name}
  - the write is rejected            -> record the error and carry on

Unlike the per-user mapping, this endpoint DOES support edit, so an update is a
single call with no window where the group has no roles.

By default roles are only ADDED: the payload is the target's current roles plus
whatever the source has on top. --replace instead mirrors the source exactly,
which will REMOVE target-only roles from a group - useful for a true mirror, and
destructive if the target was deliberately extended.

Roles absent from the target are dropped from the payload and reported rather
than sent, since the mapping would grant nothing. If that empties a group
entirely, no call is made at all - a group mapped to nothing is worse than a
group that isn't there. Run sync_roles.py first and this should not come up.

Groups that exist only on the target are never touched, and get their own sheet.
"""

import argparse
import json
import time
from datetime import datetime

from clients import ApiError, RestClient
from config import add_common_args, configure
from report import Sheet, banner, token_warning, write_workbook
import snapshots as snap

COLUMNS = [
    ("SAML Group", 68), ("On Target", 11), ("Action", 10), ("Result", 18),
    ("Role Count Sent", 15), ("Roles (source)", 60), ("Roles (target before)", 60),
    ("Roles Added", 44), ("Roles Removed (--replace)", 34),
    ("Dropped (absent on target)", 34), ("Roles Sent", 60),
    ("HTTP Status", 11), ("Error", 70),
]


def write_group(client, name, roles, exists, apply_changes):
    """Create or update one SAML group. Returns (result, status, error)."""
    if not apply_changes:
        return "dry-run", "", ""
    try:
        if exists:
            client.update_group(name, roles)
        else:
            client.create_group(name, roles)
        return "success", "200", ""
    except ApiError as e:
        # Already there despite the snapshot -> switch to an update and retry.
        if not exists and e.status in (400, 409) and "already exists" in e.message.lower():
            try:
                client.update_group(name, roles)
                return "success", "200", ""
            except ApiError as e2:
                return "error", str(e2.status), e2.message
        return "error", str(e.status), e.message


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_args(ap)
    ap.add_argument("--groups", help="comma-separated group names to process instead of all")
    ap.add_argument("--replace", action="store_true",
                    help="mirror the source exactly, REMOVING target-only roles from a "
                         "group (default is to only add missing roles)")
    args = ap.parse_args()

    cfg = configure(args)

    source = snap.group_map(cfg, "source")
    target = snap.group_map(cfg, "target")
    # ACS and REST report the same role inventory; the ACS snapshot is the one
    # fetch.py keeps, and it is what sync_roles.py wrote against.
    target_roles = snap.role_names(cfg, "target")

    names = sorted(source)
    if args.groups:
        wanted = {n.strip() for n in args.groups.split(",") if n.strip()}
        names = [n for n in names if n in wanted]
    if args.limit:
        names = names[:args.limit]

    target_only = sorted(set(target) - set(source))

    mode = "APPLY" if args.apply else "DRY RUN"
    client = RestClient(cfg, "target")

    banner("SAML GROUP SYNC", cfg, mode, [
        f"source groups:     {len(source)} "
        f"(snapshot {snap.fetched_at(cfg, 'source_groups.json')})",
        f"target groups:     {len(target)} "
        f"(snapshot {snap.fetched_at(cfg, 'target_groups.json')})",
        f"groups to process: {len(names)}",
        f"  to create:       {sum(1 for n in names if n not in target)}",
        f"target-only (never touched): {len(target_only)}",
        f"role mode:         {'replace (mirror source)' if args.replace else 'add only'}",
    ])
    if args.apply:
        token_warning(client, "target")
    print()

    rows, results, counts = [], [], {}

    for i, name in enumerate(names, 1):
        src_roles = source[name]
        exists = name in target
        before = target.get(name, set())

        dropped = sorted(src_roles - target_roles)
        grantable = src_roles & target_roles
        want = grantable if args.replace else (before | grantable)
        added = sorted(want - before)
        removed = sorted(before - want)

        if not want and not before:
            # Nothing to grant and nothing there - creating an empty group mapping
            # would be a mapping to nothing.
            action, result, status, error = "none", "nothing_grantable", "", ""
        elif want == before:
            action, result, status, error = "none", "in_sync", "", ""
        else:
            action = "update" if exists else "create"
            result, status, error = write_group(client, name, sorted(want), exists, args.apply)

        counts[result] = counts.get(result, 0) + 1

        rows.append({
            "SAML Group": name,
            "On Target": "yes" if exists else "no",
            "Action": action,
            "Result": result,
            "Role Count Sent": len(want) if action != "none" else "",
            "Roles (source)": sorted(src_roles),
            "Roles (target before)": sorted(before),
            "Roles Added": added,
            "Roles Removed (--replace)": removed,
            "Dropped (absent on target)": dropped,
            "Roles Sent": sorted(want) if action != "none" else "",
            "HTTP Status": status,
            "Error": error,
        })
        results.append({"group": name, "action": action, "result": result,
                        "status": status, "error": error})

        flag = {"success": "OK", "error": "FAIL", "in_sync": "==",
                "dry-run": "~~"}.get(result, result)
        if action != "none" or args.groups:
            print(f"  [{i:4d}/{len(names)}] {name[:58]:<58} {action:<7} {flag}"
                  + (f"  {error[:80]}" if error else ""))

        if args.apply and action != "none":
            time.sleep(cfg.sleep)

    summary = [
        ("Mode", mode),
        ("Run at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Config", cfg.path),
        ("Source stack", cfg.source.label),
        ("Target stack", cfg.target.label),
        ("Target credential", cfg.target.token_source),
        ("Role mode", "replace (mirror source)" if args.replace else "add only"),
        ("Source snapshot taken", snap.fetched_at(cfg, "source_groups.json")),
        ("Target snapshot taken", snap.fetched_at(cfg, "target_groups.json")),
        ("", ""),
        ("Groups:", ""),
        ("  groups on source", len(source)),
        ("  groups on target", len(target)),
        ("  groups processed", len(names)),
        ("  target-only groups (left untouched)", len(target_only)),
        ("", ""),
        ("Results:", ""),
    ]
    summary += [(f"  {k}", v) for k, v in sorted(counts.items())]
    summary += [
        ("", ""),
        ("Checks:", ""),
        ("  role grants added", sum(len(r["Roles Added"]) for r in rows)),
        ("  role grants removed (--replace only)",
         sum(len(r["Roles Removed (--replace)"]) for r in rows)),
        ("  groups mapping more than one role",
         sum(1 for r in rows if len(r["Roles (source)"]) > 1)),
        ("  groups mapping zero roles on the source",
         sum(1 for r in rows if not r["Roles (source)"])),
        ("  groups referencing a role absent from the target",
         sum(1 for r in rows if r["Dropped (absent on target)"])),
        ("  distinct roles absent from the target",
         len({x for r in rows for x in r["Dropped (absent on target)"]})),
    ]

    target_only_sheet = Sheet(
        "Target-Only Groups",
        [("SAML Group (on target, not on source - untouched)", 68), ("Roles", 60)],
        [{"SAML Group (on target, not on source - untouched)": n,
          "Roles": sorted(target[n])} for n in target_only])

    out = cfg.results_path(args.out or "saml_group_sync.xlsx")
    write_workbook(out, Sheet("SAML Groups", COLUMNS, rows, colour_by="Result"),
                   summary=summary, extras=[target_only_sheet])

    json_out = cfg.results_path("saml_group_results.json")
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump({"mode": mode, "counts": counts, "results": results}, f, indent=2)

    print(f"\n{'=' * 74}")
    print("SUMMARY")
    print(f"{'=' * 74}")
    for k, v in sorted(counts.items()):
        print(f"  {k:<12} {v}")
    if not args.apply:
        print("\n  DRY RUN - nothing was written. Re-run with --apply to make changes.")
    print(f"\n  Excel report: {out}")
    print(f"  JSON results: {json_out}")


if __name__ == "__main__":
    main()
