#!/usr/bin/env python3
"""
Copy every role from the source stack to the target stack - capabilities, index
permissions, default app, quotas, search filter and inherited roles - then report
what happened to each one.

    python fetch.py                   # snapshot both stacks first
    python sync_roles.py              # DRY RUN - reports, writes nothing
    python sync_roles.py --apply      # create/update roles on the target via ACS

Run this BEFORE sync_users.py. A role that does not exist on the target cannot be
granted to anyone, so any role missing here turns into a dropped grant there.

For each role in the source snapshot:
  - on the target, every setting matches  -> in_sync, no call made
  - on the target, settings differ        -> PATCH /roles/{name}
  - not on the target                     -> POST /roles
  - the write is rejected                 -> retry down the fallback chain, then
                                             record the error and keep going

Roles are written in dependency order, so a role's importedRoles exist before the
role that inherits them.

Payloads are sanitized against the target's own inventory first. Each of these is
a verified hard 400 from ACS, not a guess, which is why they are fixed up front
rather than discovered one failed call at a time:

  - capabilities the target doesn't have, or won't grant to this token
  - a defaultApp that isn't installed on the target        -> falls back to search
  - literal index names that don't exist on the target
  - srchIndexesDefault entries not covered by srchIndexesAllowed

Everything dropped gets its own report column, and dropped capabilities get their
own sheet, so nothing is lost quietly. Protected built-in roles (config
roles.protected) are never touched - ACS refuses to edit them.

Rolling back a role change means re-applying the pre-run snapshot: the target's
roles as they were are in data/target_roles.json, so copy it aside before --apply
if you want that option.
"""

import argparse
import fnmatch
import json
import time
from datetime import datetime

from clients import AcsClient, ApiError
from config import add_common_args, configure
from report import Sheet, banner, token_warning, write_workbook
import snapshots as snap

# Numeric/string role settings, compared and sent verbatim.
SCALAR_FIELDS = [
    "cumulativeRTSrchJobsQuota",
    "cumulativeSrchJobsQuota",
    "rtSrchJobsQuota",
    "srchJobsQuota",
    "srchDiskQuota",
    "srchFilter",
    "srchTimeEarliest",
    "srchTimeWin",
]
# List settings. ACS overwrites these wholesale on PATCH, so always send them in full.
LIST_FIELDS = ["capabilities", "importedRoles", "srchIndexesAllowed", "srchIndexesDefault"]

COLUMNS = [
    ("Role Name", 38), ("On Target", 11), ("Action", 10), ("Result", 11),
    ("Cap Count", 10), ("Capabilities", 60), ("Dropped Capabilities", 30),
    ("Imported Roles", 28), ("Default App (source)", 22), ("Default App (applied)", 22),
    ("Search Filter", 40), ("Indexes Allowed", 50), ("Indexes Default", 40),
    ("Dropped Indexes (absent on target)", 34),
    ("Dropped Defaults (not in allowed)", 32),
    ("srchJobsQuota", 13), ("rtSrchJobsQuota", 15), ("srchDiskQuota", 13),
    ("cumulativeSrchJobsQuota", 22), ("cumulativeRTSrchJobsQuota", 24),
    ("srchTimeEarliest", 16), ("srchTimeWin", 12), ("Differences", 40),
    ("Fallbacks Applied", 34), ("HTTP Status", 11), ("Error", 70),
]


def role_key(role):
    """Flatten an ACS role object into the field names a POST/PATCH body uses.

    GET returns the inherited-role list nested at imported.roles, but the write
    side calls that field importedRoles, so normalize to the write shape.
    """
    return {
        "name": role["name"],
        "capabilities": sorted(role.get("capabilities") or []),
        "importedRoles": sorted((role.get("imported") or {}).get("roles") or []),
        "srchIndexesAllowed": sorted(role.get("srchIndexesAllowed") or []),
        "srchIndexesDefault": sorted(role.get("srchIndexesDefault") or []),
        "defaultApp": role.get("defaultApp") or "",
        "cumulativeRTSrchJobsQuota": role.get("cumulativeRTSrchJobsQuota", 0),
        "cumulativeSrchJobsQuota": role.get("cumulativeSrchJobsQuota", 0),
        "rtSrchJobsQuota": role.get("rtSrchJobsQuota", 0),
        "srchJobsQuota": role.get("srchJobsQuota", 0),
        "srchDiskQuota": role.get("srchDiskQuota", 0),
        "srchFilter": role.get("srchFilter") or "",
        "srchTimeEarliest": role.get("srchTimeEarliest", -1),
        "srchTimeWin": role.get("srchTimeWin", -1),
    }


def topo_sort(roles):
    """Order roles so a role's importedRoles are created before the role itself.

    Roles whose parents live outside this set (built-ins like power/user) sort
    normally; cycles, if ACS ever allows one, are appended rather than dropped.
    """
    by_name = {r["name"]: r for r in roles}
    ordered, state = [], {}

    def visit(name):
        if state.get(name) == "done":
            return
        if state.get(name) == "visiting":  # cycle - break here
            return
        state[name] = "visiting"
        for parent in by_name[name]["importedRoles"]:
            if parent in by_name:
                visit(parent)
        state[name] = "done"
        ordered.append(by_name[name])

    for name in sorted(by_name):
        visit(name)
    return ordered


def index_covered(entry, allowed):
    """Is `entry` permitted by the `allowed` list, honouring ACS wildcard semantics?

    ACS enforces "srchIndexesDefault must be part of srchIndexesAllowed", where
    '*' matches all non-internal indexes and '_*' is required to match internal
    ones. A wildcard entry in srchIndexesDefault only counts as covered when the
    identical pattern appears in srchIndexesAllowed.
    """
    if entry in allowed:
        return True
    if "*" in entry:
        return False
    for pattern in allowed:
        if "*" not in pattern:
            continue
        # '*' alone never reaches internal (_-prefixed) indexes; '_*' is needed.
        if entry.startswith("_") and not pattern.startswith("_"):
            continue
        if fnmatch.fnmatchcase(entry, pattern):
            return True
    return False


def sanitize(desired, grantable, apps, indexes):
    """Strip anything the target will reject outright. Returns (payload, notes)."""
    notes = {"dropped_capabilities": [], "default_app_fallback": "",
             "dropped_indexes": [], "dropped_defaults": []}

    caps = desired["capabilities"]
    keep = [c for c in caps if c in grantable]
    if len(keep) != len(caps):
        notes["dropped_capabilities"] = sorted(set(caps) - set(keep))
    desired["capabilities"] = keep

    app = desired["defaultApp"]
    if app and app not in apps:
        notes["default_app_fallback"] = f"{app} not installed on target -> search"
        desired["defaultApp"] = "search"

    # Literal index names must exist on the target ("cannot set index name 'x':
    # index does not exist"); wildcard patterns are not validated by ACS.
    gone = set()
    for field in ("srchIndexesAllowed", "srchIndexesDefault"):
        kept = []
        for idx in desired[field]:
            if "*" in idx or idx in indexes:
                kept.append(idx)
            else:
                gone.add(idx)
        desired[field] = kept
    notes["dropped_indexes"] = sorted(gone)

    # Whatever is left in srchIndexesDefault must be covered by srchIndexesAllowed.
    # Drop the stragglers rather than widening srchIndexesAllowed, which would
    # grant access the source role never had.
    allowed = desired["srchIndexesAllowed"]
    covered = [i for i in desired["srchIndexesDefault"] if index_covered(i, allowed)]
    if len(covered) != len(desired["srchIndexesDefault"]):
        notes["dropped_defaults"] = sorted(set(desired["srchIndexesDefault"]) - set(covered))
    desired["srchIndexesDefault"] = covered

    return desired, notes


def diff_fields(desired, actual):
    """Field names where the target role doesn't match what we want."""
    out = [f for f in LIST_FIELDS if desired[f] != actual[f]]
    out += [f for f in SCALAR_FIELDS if desired[f] != actual[f]]
    if desired["defaultApp"] != actual["defaultApp"]:
        out.append("defaultApp")
    return out


def to_payload(desired, include_name):
    payload = {f: desired[f] for f in LIST_FIELDS + SCALAR_FIELDS}
    payload["defaultApp"] = desired["defaultApp"]
    if include_name:
        payload["name"] = desired["name"]
    return payload


def build_variants(desired):
    """Progressive relaxations to try in order when a write is rejected.

    Returns [(fallback_label, payload_dict)]; the first entry is the payload as
    planned. Index problems are already resolved in sanitize(), so the only
    remaining retry is dropping a defaultApp that ACS rejects for a reason the app
    inventory didn't reveal (uninstalled, not visible, and so on).
    """
    variants = [("", dict(desired))]
    if desired["defaultApp"] and desired["defaultApp"] != "search":
        relaxed = dict(desired)
        relaxed["defaultApp"] = "search"
        variants.append(('defaultApp -> "search"', relaxed))
    return variants


def write_role(client, desired, exists, apply_changes):
    """Create or update one role, walking the fallback chain on failure.

    Returns (result, http_status, error, fallback_label).
    """
    variants = build_variants(desired)

    if not apply_changes:
        return "dry-run", "", "", ""

    last_status, last_error = "", ""
    for label, candidate in variants:
        payload = to_payload(candidate, include_name=not exists)
        try:
            if exists:
                body = dict(payload)
                body.pop("name", None)
                client.update_role(desired["name"], body)
            else:
                client.create_role(payload)
            return "success", "200", "", label
        except ApiError as e:
            last_status = str(e.status)
            last_error = f"{e.code}: {e.message}".strip(": ")
            # A role that already exists gets switched to a PATCH and retried -
            # the snapshot can be stale, and 409 says so authoritatively.
            if not exists and e.status == 409:
                exists = True
                try:
                    body = dict(payload)
                    body.pop("name", None)
                    client.update_role(desired["name"], body)
                    return "success", "200", "", (label + "; existed -> PATCH").strip("; ")
                except ApiError as e2:
                    last_status = str(e2.status)
                    last_error = f"{e2.code}: {e2.message}".strip(": ")

    return "error", last_status, last_error, ""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_args(ap)
    ap.add_argument("--roles", help="comma-separated role names to process instead of all")
    args = ap.parse_args()

    cfg = configure(args)

    source_roles = snap.role_objects(cfg, "source")
    target_roles = snap.role_objects(cfg, "target")
    system_caps, grantable = snap.capabilities(cfg, "target")
    apps = snap.app_names(cfg, "target")
    indexes = snap.index_names(cfg, "target")

    target_by_name = {r["name"]: role_key(r) for r in target_roles}

    plan = [role_key(r) for r in source_roles if r["name"] not in cfg.protected_roles]
    skipped_protected = sorted({r["name"] for r in source_roles} & cfg.protected_roles)

    if args.roles:
        wanted = {n.strip() for n in args.roles.split(",") if n.strip()}
        plan = [r for r in plan if r["name"] in wanted]
    plan = topo_sort(plan)
    if args.limit:
        plan = plan[:args.limit]

    mode = "APPLY" if args.apply else "DRY RUN"
    client = AcsClient(cfg, "target")

    banner("ROLE SYNC", cfg, mode, [
        f"source roles:        {len(source_roles)} "
        f"(snapshot {snap.fetched_at(cfg, 'source_roles.json')})",
        f"target roles:        {len(target_roles)} "
        f"(snapshot {snap.fetched_at(cfg, 'target_roles.json')})",
        f"roles to process:    {len(plan)}",
        f"  already on target: {sum(1 for r in plan if r['name'] in target_by_name)}",
        f"  to create:         {sum(1 for r in plan if r['name'] not in target_by_name)}",
        f"protected skipped:   {', '.join(skipped_protected) or 'none'}",
        f"target grantable capabilities: {len(grantable)}",
    ])
    if args.apply:
        token_warning(client, "target")
    print()

    rows, results, counts = [], [], {}
    cap_gap_roles = {}

    for i, src in enumerate(plan, 1):
        name = src["name"]
        source_app = src["defaultApp"]
        desired, notes = sanitize(dict(src), grantable, apps, indexes)
        exists = name in target_by_name

        for capability in notes["dropped_capabilities"]:
            cap_gap_roles.setdefault(capability, set()).add(name)

        differences = []
        if exists:
            differences = diff_fields(desired, target_by_name[name])
            if not differences:
                action, result, status, error, fallback = "none", "in_sync", "", "", ""
            else:
                action = "update"
                result, status, error, fallback = write_role(client, desired, True, args.apply)
        else:
            action = "create"
            result, status, error, fallback = write_role(client, desired, False, args.apply)

        counts[result] = counts.get(result, 0) + 1

        rows.append({
            "Role Name": name,
            "On Target": "yes" if exists else "no",
            "Action": action,
            "Result": result,
            "Cap Count": len(desired["capabilities"]),
            "Capabilities": desired["capabilities"],
            "Dropped Capabilities": notes["dropped_capabilities"],
            "Imported Roles": desired["importedRoles"],
            "Default App (source)": source_app,
            "Default App (applied)": desired["defaultApp"],
            "Search Filter": desired["srchFilter"],
            "Indexes Allowed": desired["srchIndexesAllowed"],
            "Indexes Default": desired["srchIndexesDefault"],
            "Dropped Indexes (absent on target)": notes["dropped_indexes"],
            "Dropped Defaults (not in allowed)": notes["dropped_defaults"],
            "srchJobsQuota": desired["srchJobsQuota"],
            "rtSrchJobsQuota": desired["rtSrchJobsQuota"],
            "srchDiskQuota": desired["srchDiskQuota"],
            "cumulativeSrchJobsQuota": desired["cumulativeSrchJobsQuota"],
            "cumulativeRTSrchJobsQuota": desired["cumulativeRTSrchJobsQuota"],
            "srchTimeEarliest": desired["srchTimeEarliest"],
            "srchTimeWin": desired["srchTimeWin"],
            "Differences": differences,
            "Fallbacks Applied": "; ".join(
                x for x in [notes["default_app_fallback"], fallback] if x),
            "HTTP Status": status,
            "Error": error,
        })
        results.append({"role": name, "action": action, "result": result,
                        "status": status, "error": error})

        flag = {"success": "OK", "error": "FAIL", "in_sync": "==",
                "dry-run": "~~"}.get(result, result)
        print(f"  [{i:4d}/{len(plan)}] {name:<40} {action:<7} {flag}"
              + (f"  {error[:90]}" if error else ""))

        if args.apply and action != "none":
            time.sleep(cfg.sleep)

    for name in skipped_protected:
        rows.append({"Role Name": name, "On Target": "yes", "Action": "skip",
                     "Result": "skipped",
                     "Error": "protected built-in; ACS does not support editing it"})

    cap_gaps = [
        (c,
         "not in target systemCapabilities" if c not in system_caps
         else "on the target but not grantable by this token",
         names)
        for c, names in sorted(cap_gap_roles.items())
    ]

    summary = [
        ("Mode", mode),
        ("Run at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Config", cfg.path),
        ("Source stack", cfg.source.label),
        ("Target stack", cfg.target.label),
        ("Target credential", cfg.target.token_source),
        ("Source snapshot taken", snap.fetched_at(cfg, "source_roles.json")),
        ("Target snapshot taken", snap.fetched_at(cfg, "target_roles.json")),
        ("", ""),
        ("Roles:", ""),
        ("  roles in source snapshot", len(source_roles)),
        ("  roles in target snapshot", len(target_roles)),
        ("  roles processed", len(plan)),
        ("  protected roles skipped", skipped_protected),
        ("", ""),
        ("Results:", ""),
    ]
    summary += [(f"  {k}", v) for k, v in sorted(counts.items())]
    summary += [
        ("", ""),
        ("Sanitizing (dropped before the first call):", ""),
        ("  distinct capabilities dropped", len(cap_gaps)),
        ("  roles with a dropped capability", len({n for _, _, ns in cap_gaps for n in ns})),
        ("  roles with a defaultApp fallback",
         sum(1 for r in rows if r.get("Default App (applied)") == "search"
             and r.get("Default App (source)") not in ("search", "", None))),
        ("  roles with indexes dropped (absent on target)",
         sum(1 for r in rows if r.get("Dropped Indexes (absent on target)"))),
        ("  distinct indexes dropped (absent on target)",
         len({i for r in rows for i in (r.get("Dropped Indexes (absent on target)") or [])})),
        ("  roles with srchIndexesDefault entries dropped",
         sum(1 for r in rows if r.get("Dropped Defaults (not in allowed)"))),
    ]

    gaps_sheet = Sheet(
        "Capability Gaps",
        [("Capability", 34), ("Reason Dropped", 38), ("Roles Affected", 14), ("Role Names", 80)],
        [{"Capability": c, "Reason Dropped": reason,
          "Roles Affected": len(names), "Role Names": sorted(names)}
         for c, reason, names in cap_gaps])

    out = cfg.results_path(args.out or "role_sync.xlsx")
    write_workbook(out, Sheet("Role Sync", COLUMNS, rows, colour_by="Result", freeze="B2"),
                   summary=summary, extras=[gaps_sheet])

    json_out = cfg.results_path("role_sync_results.json")
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
