#!/usr/bin/env python3
"""
Migrate SAML users and their roles from the source stack to the target stack.

    python fetch.py                   # snapshot both stacks first
    python sync_users.py              # DRY RUN - reports, writes nothing
    python sync_users.py --apply      # write via /services/admin/SAML-user-role-map

Every SAML user on the SOURCE is considered, regardless of what they look like on
the target:

    not on the target        -> CREATE the mapping with their source roles
    on the target, missing   -> ADD the missing roles to their existing mapping
    on the target, complete  -> in_sync, no call made

Roles are only ever ADDED. Nothing is removed, and users that exist only on the
target are never touched - they are listed on their own report sheet.

"Missing" is judged against the user's EFFECTIVE roles on the target, not just
their per-user mapping, because a SAML group mapping grants roles without
appearing in the per-user map. Judging by the mapping alone would rewrite users
who already have everything via a group, for no gain and with a real cost: the
write is not atomic (see below).

The mapping endpoint has no edit action, so an update is remove-then-create. In
between, the user briefly has no mapping at all. That is why:

  - the prior roles are journalled BEFORE the write, not after it succeeds
  - a user who needs nothing is never written to
  - the create is retried on 409 while the cluster converges

Held back by default:

  roles absent on the target   dropped from that user's payload and reported,
                               rather than failing the whole user. Run
                               sync_roles.py first and this should be empty.
  accounts with no SAML
  mapping on the source        local/service accounts - writing a SAML mapping
                               for them would invent one.
                               --include-non-saml overrides.

Undo any run with: python rollback_users.py --journal <file>
"""

import argparse
import json
import os
import time
from datetime import datetime

from clients import RestClient
from config import add_common_args, configure
from report import Sheet, banner, token_warning, write_workbook
import snapshots as snap

# What happened to each user, and the one-line explanation shown in the report.
CATEGORY_NOTE = {
    "create": "not on the target - mapping created with their source roles",
    "add_roles": "on the target but missing roles - the missing ones were added",
    "in_sync": "already has every source role on the target - left alone",
    "no_source_roles": "no roles on the source beyond the baseline - nothing to copy",
    "nothing_grantable": "every missing source role is absent from the target",
    "non_saml_skipped": "no SAML mapping on the source (local/service account)",
    "excluded": "filtered out by config (exclude_users / exclude_patterns)",
}

# Order they are printed in, most interesting first.
CATEGORY_ORDER = ["create", "add_roles", "in_sync", "no_source_roles",
                  "nothing_grantable", "non_saml_skipped", "excluded"]

COLUMNS = [
    ("User", 34), ("Category", 20), ("Action", 10), ("Result", 12),
    ("On Target", 11), ("Source Roles", 52), ("Target Effective Before", 52),
    ("Target Mapped Before", 46), ("Roles Added", 52), ("Added Count", 12),
    ("Dropped (absent on target)", 40), ("Dropped Count", 14),
    ("Final Mapping Sent", 52), ("Final Count", 12),
    ("Verified", 18), ("HTTP Status", 12), ("Detail", 60),
]


def build_plan(cfg, args):
    """Decide what to do for every user on the source. Returns (plan, context)."""
    src_effective = snap.effective_roles(cfg, "source")
    src_map = snap.user_map(cfg, "source")
    tgt_effective = snap.effective_roles(cfg, "target")
    tgt_map = snap.user_map(cfg, "target")
    target_roles = snap.role_names(cfg, "target")
    baseline = cfg.baseline_role
    # The config sets the policy; --include-non-saml overrides it for one run.
    require_saml = cfg.require_saml_mapping_on_source and not args.include_non_saml

    # Users known on the source from either view. A user can be in the mapping
    # but absent from ACS (mapped and never logged in), so neither list alone
    # is complete.
    source_users = sorted(set(src_effective) | set(src_map))

    plan = []
    for user in source_users:
        if args.source_roles == "mapping":
            source = src_map.get(user, set()) - {baseline}
        else:
            source = src_effective.get(user, set()) - {baseline}

        on_target = user in tgt_effective or user in tgt_map
        effective_now = tgt_effective.get(user, set())
        mapped_now = tgt_map.get(user, set())

        row = {"user": user, "on_target": on_target, "source": source,
               "effective_before": effective_now, "mapped_before": mapped_now,
               "dropped": [], "to_add": set(), "final": mapped_now}

        if cfg.excluded(user):
            plan.append({**row, "category": "excluded", "action": "skip"})
            continue

        # Local/service accounts never had a SAML mapping on the source.
        if require_saml and user not in src_map:
            plan.append({**row, "category": "non_saml_skipped", "action": "skip"})
            continue

        if not source:
            plan.append({**row, "category": "no_source_roles", "action": "none"})
            continue

        dropped = sorted(source - target_roles)
        grantable = source & target_roles
        # Judged against EFFECTIVE roles - a group may already grant these.
        to_add = grantable - effective_now

        if not to_add:
            category = "nothing_grantable" if dropped and not grantable else "in_sync"
            plan.append({**row, "category": category, "action": "none",
                         "dropped": dropped})
            continue

        # The write replaces the whole mapping, so send the union: everything
        # already mapped, plus what is missing, plus the baseline role.
        final = mapped_now | to_add | {baseline}
        plan.append({**row,
                     "category": "create" if not on_target else "add_roles",
                     "action": "create" if not mapped_now else "update",
                     "dropped": dropped, "to_add": to_add, "final": final})

    context = {
        "target_only_users": sorted(set(tgt_effective) - set(source_users)),
        "source_user_count": len(source_users),
        "target_user_count": len(tgt_effective),
        "target_role_count": len(target_roles),
        "source_fetched": snap.fetched_at(cfg, "source_users.json"),
        "target_fetched": snap.fetched_at(cfg, "target_users.json"),
    }
    return plan, context


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_args(ap)
    ap.add_argument("--source-roles", choices=("effective", "mapping"), default="effective",
                    help="which source roles count as the user's: 'effective' includes "
                         "roles granted by SAML groups, 'mapping' is the explicit "
                         "per-user map only (default: effective)")
    ap.add_argument("--include-non-saml", action="store_true",
                    help="also process source users with no SAML mapping "
                         "(local/service accounts)")
    ap.add_argument("--users", help="comma-separated usernames to process instead of all")
    ap.add_argument("--settle", type=float,
                    help="seconds to wait before the bulk verification pass")
    args = ap.parse_args()

    cfg = configure(args)
    settle = args.settle if args.settle is not None else cfg.settle

    plan, ctx = build_plan(cfg, args)

    if args.users:
        wanted = {u.strip() for u in args.users.split(",") if u.strip()}
        plan = [p for p in plan if p["user"] in wanted]

    todo = [p for p in plan if p["action"] in ("create", "update")]
    if args.limit:
        keep = {p["user"] for p in todo[:args.limit]}
        todo = [p for p in todo if p["user"] in keep]
        plan = [p for p in plan
                if p["action"] not in ("create", "update") or p["user"] in keep]

    counts_by_cat = {}
    for p in plan:
        counts_by_cat[p["category"]] = counts_by_cat.get(p["category"], 0) + 1

    missing_roles = {}
    for p in plan:
        for r in p["dropped"]:
            missing_roles.setdefault(r, []).append(p["user"])

    mode = "APPLY" if args.apply else "DRY RUN"
    client = RestClient(cfg, "target")

    banner("SAML USER SYNC", cfg, mode, [
        f"source users:   {ctx['source_user_count']}  (snapshot {ctx['source_fetched']})",
        f"target users:   {ctx['target_user_count']}  (snapshot {ctx['target_fetched']})",
        f"source roles counted as: {args.source_roles}",
    ])
    for cat in CATEGORY_ORDER:
        if cat in counts_by_cat:
            print(f"  {cat:<20} {counts_by_cat[cat]:>5}   {CATEGORY_NOTE[cat]}")
    print(f"\n  users to write:   {len(todo)}"
          f"  (create {sum(1 for p in todo if p['category'] == 'create')},"
          f" add roles {sum(1 for p in todo if p['category'] == 'add_roles')})")
    print(f"  role grants:      {sum(len(p['to_add']) for p in todo)}")
    print(f"  roles absent on target (dropped): {len(missing_roles)} distinct, "
          f"{sum(len(v) for v in missing_roles.values())} grants")
    print(f"  target-only users (never touched): {len(ctx['target_only_users'])}")
    if args.apply:
        token_warning(client, "target")
    print()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    journal_path = cfg.results_path(f"user_journal_{stamp}.jsonl")

    rows, counts = [], {}
    journal = None
    if args.apply:
        journal = open(journal_path, "w", encoding="utf-8")
        journal.write(json.dumps({
            "_meta": True, "kind": "users",
            "source": cfg.source.label, "target": cfg.target.label,
            "source_roles": args.source_roles,
            "started_at": datetime.now().isoformat(timespec="seconds"),
        }) + "\n")
        journal.flush()

    try:
        for p in plan:
            status, detail = "", ""

            # For anything that isn't written, Result restates the category, so
            # "in_sync" never has to stand in for "wanted roles the target
            # doesn't have".
            if p["action"] in ("skip", "none"):
                result = p["category"]
            elif not args.apply:
                result = "dry-run"
            else:
                # Journal BEFORE mutating. An update removes the existing mapping
                # before recreating it, so a hard failure can leave the user with
                # no mapping at all - the prior roles have to be on disk before
                # that window opens.
                journal.write(json.dumps({
                    "user": p["user"],
                    "existed": bool(p["mapped_before"]),
                    "roles_before": sorted(p["mapped_before"]),
                    "roles_intended": sorted(p["final"]),
                    "added": sorted(p["to_add"]),
                    "at": datetime.now().isoformat(timespec="seconds"),
                }) + "\n")
                journal.flush()

                # The snapshot already told us whether a mapping exists, so skip
                # the existence probe - it is one wasted call per user.
                ok, detail, _ = client.replace_user_roles(
                    p["user"], sorted(p["final"]), exists=bool(p["mapped_before"]))
                result, status = ("success", "200") if ok else ("error", "")
                time.sleep(cfg.sleep)

            counts[result] = counts.get(result, 0) + 1
            rows.append({
                "User": p["user"],
                "Category": p["category"],
                "Action": p["action"],
                "Result": result,
                "On Target": "yes" if p["on_target"] else "no",
                "Source Roles": sorted(p["source"]),
                "Target Effective Before": sorted(p["effective_before"]),
                "Target Mapped Before": sorted(p["mapped_before"]),
                "Roles Added": sorted(p["to_add"]),
                "Added Count": len(p["to_add"]),
                "Dropped (absent on target)": p["dropped"],
                "Dropped Count": len(p["dropped"]),
                "Final Mapping Sent": sorted(p["final"]) if p["action"] in ("create", "update") else "",
                "Final Count": len(p["final"]) if p["action"] in ("create", "update") else "",
                "HTTP Status": status,
                "Detail": detail,
            })

            if result == "error":
                print(f"  FAIL {p['user']:<34} {detail[:80]}")
            elif result == "success":
                done = counts["success"]
                if done <= 3 or done % 50 == 0:
                    print(f"  [{done:4d}/{len(todo)}] {p['user'][:40]:<40} "
                          f"+{len(p['to_add'])} roles  ({detail})")
    finally:
        if journal:
            journal.close()

    # Bulk verification. Per-user readback is unreliable for a few seconds after a
    # write, so confirm the whole set at once, after everything has settled.
    verify = {}
    if args.apply and counts.get("success"):
        print(f"\n  waiting {settle}s for the cluster to settle, then verifying...")
        time.sleep(settle)
        actual = client.user_role_map()
        exact = absent = differs = 0
        by_user = {r["User"]: r for r in rows}
        for p in plan:
            if p["action"] not in ("create", "update"):
                continue
            got, want = set(actual.get(p["user"], [])), set(p["final"])
            if got == want:
                exact += 1
                note = "yes"
            elif not got:
                absent += 1
                note = "MISSING MAPPING"
            else:
                differs += 1
                note = f"differs ({len(want - got)} absent)"
            by_user[p["user"]]["Verified"] = note
        verify = {"verified exact": exact, "missing mapping": absent, "differs": differs}
        print(f"  verified exact: {exact}   missing mapping: {absent}   differs: {differs}")

    summary = [
        ("Mode", mode),
        ("Run at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Config", cfg.path),
        ("Source stack", cfg.source.label),
        ("Target stack", cfg.target.label),
        ("Source credential", cfg.source.token_source),
        ("Target credential", cfg.target.token_source),
        ("Source roles counted as", args.source_roles),
        ("Non-SAML accounts included", "yes" if args.include_non_saml else "no"),
        ("Source snapshot taken", ctx["source_fetched"]),
        ("Target snapshot taken", ctx["target_fetched"]),
        ("", ""),
        ("Users by category:", ""),
    ]
    for cat in CATEGORY_ORDER:
        if cat in counts_by_cat:
            summary.append((f"  {cat}", counts_by_cat[cat]))
            summary.append((f"    {CATEGORY_NOTE[cat]}", ""))
    summary += [
        ("", ""),
        ("Writes:", ""),
        ("  users to write", len(todo)),
        ("  mappings created", sum(1 for p in todo if p["category"] == "create")),
        ("  mappings extended", sum(1 for p in todo if p["category"] == "add_roles")),
        ("  role grants added", sum(len(p["to_add"]) for p in todo)),
        ("  grants dropped (role absent on target)",
         sum(len(p["dropped"]) for p in plan if p["action"] in ("create", "update"))),
        ("  distinct roles absent on target", len(missing_roles)),
        ("  target-only users (never touched)", len(ctx["target_only_users"])),
        ("", ""),
        ("Results:", ""),
    ]
    summary += [(f"  {k}", v) for k, v in sorted(counts.items())]
    if verify:
        summary += [("", ""), ("Verification (bulk re-read):", "")]
        summary += [(f"  {k}", v) for k, v in verify.items()]
    summary += [("", ""),
                ("Rollback journal", journal_path if args.apply else "(none - dry run)")]

    absent_sheet = Sheet(
        "Roles Absent On Target",
        [("Role (on source, missing on target)", 52), ("Users Wanting It", 18), ("Users", 80)],
        [{"Role (on source, missing on target)": r, "Users Wanting It": len(u), "Users": u}
         for r, u in sorted(missing_roles.items(), key=lambda kv: -len(kv[1]))])

    target_only_sheet = Sheet(
        "Target-Only Users",
        [("User (on target, not on source - untouched)", 46), ("Effective Roles", 80)],
        [{"User (on target, not on source - untouched)": u,
          "Effective Roles": sorted(snap.effective_roles(cfg, "target").get(u, set()))}
         for u in ctx["target_only_users"]])

    out = cfg.results_path(args.out or "user_sync.xlsx")
    write_workbook(out, Sheet("User Sync", COLUMNS, rows, colour_by="Result"),
                   summary=summary, extras=[absent_sheet, target_only_sheet])

    print(f"\n{'=' * 74}")
    print("SUMMARY")
    print(f"{'=' * 74}")
    for k, v in sorted(counts.items()):
        print(f"  {k:<12} {v}")
    if not args.apply:
        print("\n  DRY RUN - nothing was written. Re-run with --apply to make changes.")
    else:
        print(f"\n  Rollback journal: {journal_path}")
        print(f"  Undo with: python rollback_users.py --journal "
              f"{os.path.basename(journal_path)}")
    print(f"  Excel report: {out}")


if __name__ == "__main__":
    main()
