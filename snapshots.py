#!/usr/bin/env python3
"""
Typed readers for the snapshots fetch.py writes.

Every sync script plans from these files rather than from live API calls, so the
plan shown by a dry run is exactly the plan that --apply executes. Each reader
fails with the command to run rather than a KeyError.
"""

import json
import os
import sys


def load(cfg, name):
    path = cfg.data_path(name)
    if not os.path.exists(path):
        print(f"ERROR: {path} not found.\n"
              f"       Run: python fetch.py --config {cfg.path}")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def fetched_at(cfg, name):
    return load(cfg, name).get("fetched_at", "(unknown)")


def effective_roles(cfg, role):
    """{username: set(roles)} - a user's roles as the stack actually computes
    them, including anything granted by a SAML group."""
    return {u["name"]: set(u.get("roles") or [])
            for u in load(cfg, f"{role}_users.json")["users"]}


def user_map(cfg, role):
    """{username: set(roles)} - the per-user SAML mapping, which is what writes
    land on. A subset of effective_roles: group-derived roles never appear here."""
    return {k: set(v) for k, v in load(cfg, f"{role}_user_map.json")["user_roles"].items()}


def group_map(cfg, role):
    """{group: set(roles)}"""
    return {k: set(v) for k, v in load(cfg, f"{role}_groups.json")["groups"].items()}


def role_objects(cfg, role):
    """Full ACS role objects."""
    return load(cfg, f"{role}_roles.json")["roles"]


def role_names(cfg, role):
    return {r["name"] for r in role_objects(cfg, role)}


def capabilities(cfg, role):
    """-> (system, grantable) as sets."""
    d = load(cfg, f"{role}_caps.json")
    return set(d["systemCapabilities"]), set(d["grantableCapabilities"])


def app_names(cfg, role):
    return set(load(cfg, f"{role}_apps.json")["apps"])


def index_names(cfg, role):
    return set(load(cfg, f"{role}_indexes.json")["indexes"])
