#!/usr/bin/env python3
"""
Snapshot both stacks into the data dir. Every sync script reads these snapshots
rather than hitting the APIs while it plans, so a dry run is reproducible and the
plan you review is the plan that gets applied.

    python fetch.py                     # everything, both stacks
    python fetch.py --only roles        # roles + capabilities + apps + indexes
    python fetch.py --only users        # users + SAML user map + SAML groups
    python fetch.py --stack target      # refresh one side only

Written per stack ({role} is "source" or "target"), all under the data dir:

    {role}_roles.json        full role objects from ACS GET /roles
    {role}_caps.json         ACS GET /capabilities (system + grantable)
    {role}_apps.json         app names        (validates a role's defaultApp)
    {role}_indexes.json      index names      (validates srchIndexes*)
    {role}_users.json        ACS GET /users - effective roles per user
    {role}_user_map.json     REST SAML-user-role-map - the per-user mapping we write
    {role}_groups.json       REST SAML-groups - grants roles without touching users

Both the per-user map AND the group map are captured because a SAML user's
effective roles can come from either one. Only the per-user map is writable per
user, so it is the difference between them that says whether a user is genuinely
missing roles or already getting them from a group.
"""

import argparse
import json
from datetime import datetime

from clients import AcsClient, RestClient
from config import add_common_args, configure
from report import token_warning

GROUPS = ("roles", "users")


def save(cfg, name, obj):
    path = cfg.data_path(name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    return path


def stamped(stack, payload):
    return {"fetched_at": datetime.now().isoformat(timespec="seconds"),
            "stack": stack.label, **payload}


def fetch_stack(cfg, role, groups):
    stack = cfg.stack(role)
    print(f"\n{role.upper()}  {stack.label}")
    print(f"  credential: {stack.token_source}")

    acs = AcsClient(cfg, role)
    rest = RestClient(cfg, role)
    token_warning(acs, role)

    if "roles" in groups:
        print("  ACS  /roles ... ", end="", flush=True)
        roles = acs.list_roles()
        save(cfg, f"{role}_roles.json", stamped(stack, {"roles": roles}))
        print(len(roles))

        print("  ACS  /capabilities ... ", end="", flush=True)
        system, grantable = acs.capabilities()
        save(cfg, f"{role}_caps.json", stamped(stack, {
            "systemCapabilities": sorted(system),
            "grantableCapabilities": sorted(grantable)}))
        print(f"{len(system)} system, {len(grantable)} grantable")

        # Only the target's inventory is used for sanitizing, but capturing both
        # makes the "what does the target not have" question answerable offline.
        print("  ACS  /apps/victoria ... ", end="", flush=True)
        apps = acs.app_names()
        save(cfg, f"{role}_apps.json", stamped(stack, {"apps": sorted(apps)}))
        print(len(apps))

        print("  ACS  /indexes ... ", end="", flush=True)
        indexes = acs.index_names()
        save(cfg, f"{role}_indexes.json", stamped(stack, {"indexes": sorted(indexes)}))
        print(len(indexes))

    if "users" in groups:
        print("  ACS  /users ... ", end="", flush=True)
        users = acs.list_users()
        save(cfg, f"{role}_users.json", stamped(stack, {"users": users}))
        print(len(users))

        print("  REST SAML-user-role-map ... ", end="", flush=True)
        user_map = rest.user_role_map()
        save(cfg, f"{role}_user_map.json", stamped(stack, {"user_roles": user_map}))
        print(len(user_map))

        print("  REST SAML-groups ... ", end="", flush=True)
        groups_map = rest.group_map()
        save(cfg, f"{role}_groups.json", stamped(stack, {"groups": groups_map}))
        print(len(groups_map))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    # fetch.py never writes to a stack, so the shared write flags don't apply.
    ap.add_argument("--config", help="path to config.json")
    ap.add_argument("--source-token", help="source stack token; skips AWS entirely")
    ap.add_argument("--target-token", help="target stack token; skips AWS entirely")
    ap.add_argument("--stack", choices=("source", "target"),
                    help="only snapshot one side (default: both)")
    ap.add_argument("--only", choices=GROUPS, action="append",
                    help="only these groups of data (repeatable; default: all)")
    args = ap.parse_args()

    cfg = configure(args)
    groups = set(args.only) if args.only else set(GROUPS)
    roles = [args.stack] if args.stack else ["source", "target"]

    print(f"\n{'=' * 74}")
    print("FETCH snapshots")
    print(f"  config: {cfg.path}")
    print(f"  data:   {cfg.data_dir}")
    print(f"{'=' * 74}")

    for role in roles:
        fetch_stack(cfg, role, groups)

    print(f"\n  Snapshots written to {cfg.data_dir}")


if __name__ == "__main__":
    main()
