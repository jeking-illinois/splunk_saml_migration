#!/usr/bin/env python3
"""
Check that both stacks are reachable and that the credentials work, before
anything else is attempted.

    python probe.py

Four endpoints are tested, because a token that works on one API does not
necessarily work on the other, and the two hostnames are completely different
services:

    source ACS    GET /roles                        can we read the source?
    source REST   GET /services/server/info         is :8089 reachable at all?
    target ACS    GET /roles                        can we read the target?
    target REST   GET /services/server/info         the only path that can WRITE
                                                    SAML mappings

Also reported, because each has burned us at least once:

    token identity and expiry   a token that expires mid-run leaves a partially
                                migrated stack
    server GUID                 proves the two hostnames are actually two
                                different instances. Roles and users are NOT
                                replicated between search heads, so pointing both
                                halves of the config at the same instance would
                                "succeed" while doing nothing
    write capability            current-context roles on the target, so a missing
                                admin role is found now rather than on user 400
                                of 800

Exit code 0 if everything passed, 1 otherwise.
"""

import argparse
from datetime import datetime

from clients import AcsClient, ApiError, RestClient, token_expiry, token_identity
from config import ConfigError, add_common_args, configure
from report import banner


def check(label, fn):
    """Run one probe. Returns (ok, detail)."""
    print(f"  {label:<44} ", end="", flush=True)
    try:
        detail = fn()
        print(f"PASS   {detail}")
        return True, detail
    except ApiError as e:
        print(f"FAIL   HTTP {e.status} {e.message[:100]}")
        return False, f"HTTP {e.status} {e.message}"
    except ConfigError as e:
        print(f"FAIL   {e}")
        return False, str(e)
    except Exception as e:
        print(f"FAIL   {type(e).__name__}: {e}")
        return False, f"{type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_args(ap)
    args = ap.parse_args()

    cfg = configure(args)
    banner("CONNECTIVITY PROBE", cfg, "READ ONLY")

    results, guids = [], {}

    for role in ("source", "target"):
        stack = cfg.stack(role)
        print(f"\n{role.upper()}  {stack.label}")
        print(f"  ACS  {stack.acs_base}")
        print(f"  REST {stack.rest_base}")
        print(f"  credential: {stack.token_source}")

        # Resolving the token is itself a test - SSM may be unreachable, the
        # profile may be wrong, the parameter may not exist.
        try:
            token = stack.token
        except ConfigError as e:
            print(f"  credential resolution                        FAIL   {e}")
            results.append((f"{role} credential", False))
            continue

        who = token_identity(token)
        when, expired = token_expiry(token)
        print(f"  token identity: {who or '(no sub claim)'}")
        if when:
            days = (when - datetime.now(when.tzinfo)).days
            note = "*** EXPIRED ***" if expired else f"{days}d left"
            print(f"  token expires:  {when.strftime('%Y-%m-%d %H:%M')} ({note})")
            if expired:
                print("  WARNING: this token is expired; every call below will fail")
            elif days <= 3:
                print("  WARNING: refresh this credential before a long run")
        else:
            print("  token expires:  (not a JWT, or no exp claim)")

        acs = AcsClient(cfg, role)
        rest = RestClient(cfg, role)

        ok, _ = check(f"{role} ACS  GET /roles",
                      lambda: f"{len(acs.list_roles())} roles")
        results.append((f"{role} ACS /roles", ok))

        def server_info(rest=rest, role=role):
            info = rest.server_info()
            guids[role] = info["guid"]
            return (f"{info['serverName']} v{info['version']} "
                    f"guid={info['guid'][:8]}...")

        ok, _ = check(f"{role} REST GET /services/server/info", server_info)
        results.append((f"{role} REST /server/info", ok))

        def context(rest=rest):
            ctx = rest.current_context()
            return f"{ctx['username']} roles={','.join(sorted(ctx['roles'])) or 'none'}"

        ok, _ = check(f"{role} REST authenticated as", context)
        results.append((f"{role} REST current-context", ok))

    # Roles and SAML mappings are per-search-head and are NOT replicated. If both
    # halves of the config resolve to the same instance, a migration would report
    # complete success while changing nothing.
    print()
    if len(guids) == 2:
        if guids["source"] == guids["target"]:
            print("  ERROR: source and target are the SAME Splunk instance "
                  f"(guid {guids['source']}).")
            print("         Roles and SAML mappings are per-instance; migrating a stack "
                  "onto itself\n         would do nothing. Check stacks.* in your config.")
            results.append(("distinct instances", False))
        else:
            print("  source and target are distinct instances (different GUIDs)  PASS")
            results.append(("distinct instances", True))

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{'=' * 74}")
    print(f"  {passed}/{len(results)} checks passed")
    for name, ok in results:
        if not ok:
            print(f"    FAILED: {name}")
    print(f"{'=' * 74}")

    if passed == len(results):
        print("\n  All checks passed. Next: python fetch.py")
        raise SystemExit(0)
    print("\n  Fix the failures above before running fetch.py.")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
