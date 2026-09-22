#!/usr/bin/env python3
"""
Run the whole migration in the order that actually works.

    python migrate.py                 # probe, fetch, then DRY RUN all three syncs
    python migrate.py --apply         # the same, writing for real
    python migrate.py --skip-fetch    # reuse the snapshots already on disk

The order is not cosmetic - each stage depends on the one before it:

    1. probe               fail now if a credential is dead, not halfway through
    2. fetch               one snapshot both syncs plan against
    3. sync_roles          a role that doesn't exist on the target cannot be
                           granted, so every role missing here becomes a dropped
                           grant in stages 4 and 5
    4. sync_saml_groups    group mappings grant roles without touching any user;
                           doing them first means stage 5 sees those roles as
                           already granted and skips writes it doesn't need
    5. sync_users          per-user mappings, for whatever the groups don't cover
    6. re-fetch            so the snapshots on disk describe the stack as it is
                           now, not as it was before the run

With --apply, a stage that fails stops the run: continuing would write against
assumptions that have just been shown to be wrong. Each stage's own report lands
in the results dir as usual, and sync_users still writes its rollback journal.

This is a convenience wrapper. Anything subtle - a partial re-run, --limit, one
user, a rollback - is better done by calling the individual scripts, which all
take the same --config.
"""

import argparse
import os
import subprocess
import sys
import time

from config import add_common_args, configure
from report import banner

HERE = os.path.dirname(os.path.abspath(__file__))


def run(script, cfg_path, extra=(), apply_changes=False):
    """Run one stage as its own process. Returns its exit code.

    Each stage runs with cwd=HERE, so the config path is made absolute first -
    otherwise a relative --config given from another directory would not resolve.
    """
    cmd = [sys.executable, os.path.join(HERE, script),
           "--config", os.path.abspath(cfg_path)]
    cmd += list(extra)
    if apply_changes:
        cmd.append("--apply")
    print(f"\n{'#' * 74}")
    print(f"# {script} {' '.join(cmd[4:])}")
    print(f"{'#' * 74}", flush=True)
    return subprocess.run(cmd, cwd=HERE).returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_args(ap)
    ap.add_argument("--skip-probe", action="store_true", help="skip the connectivity probe")
    ap.add_argument("--skip-fetch", action="store_true",
                    help="reuse the snapshots already in the data dir")
    ap.add_argument("--skip-roles", action="store_true", help="skip the role sync")
    ap.add_argument("--skip-groups", action="store_true", help="skip the SAML group sync")
    ap.add_argument("--skip-users", action="store_true", help="skip the user sync")
    ap.add_argument("--continue-on-error", action="store_true",
                    help="keep going after a stage fails (default is to stop)")
    args = ap.parse_args()

    cfg = configure(args)
    mode = "APPLY" if args.apply else "DRY RUN"
    banner("FULL MIGRATION", cfg, mode, [
        f"results: {cfg.results_dir}",
        f"data:    {cfg.data_dir}",
    ])

    # --out would collide across stages, so each keeps its own default name.
    passthrough = []
    if args.sleep is not None:
        passthrough += ["--sleep", str(args.sleep)]

    stages = []
    if not args.skip_probe:
        stages.append(("probe.py", [], False))
    if not args.skip_fetch:
        stages.append(("fetch.py", [], False))
    if not args.skip_roles:
        stages.append(("sync_roles.py", passthrough, True))
    if not args.skip_groups:
        stages.append(("sync_saml_groups.py", passthrough, True))
    if not args.skip_users:
        stages.append(("sync_users.py", passthrough, True))
    if args.apply and not args.skip_fetch:
        # Leave the snapshots describing the stack as it is now.
        stages.append(("fetch.py", [], False))

    started = time.time()
    outcomes = []
    for script, extra, writes in stages:
        code = run(script, cfg.path, extra, apply_changes=args.apply and writes)
        outcomes.append((script, code))
        if code != 0 and not args.continue_on_error:
            print(f"\n  {script} exited {code} - stopping.")
            print("  Nothing after this stage ran. Fix the cause and re-run; "
                  "completed stages are idempotent.")
            break

    print(f"\n{'=' * 74}")
    print(f"MIGRATION {mode} - {time.time() - started:.0f}s")
    print(f"{'=' * 74}")
    for script, code in outcomes:
        print(f"  {script:<24} {'ok' if code == 0 else f'EXIT {code}'}")
    print(f"\n  Reports: {cfg.results_dir}")
    if not args.apply:
        print("  DRY RUN - nothing was written. Review the reports, then re-run "
              "with --apply.")

    raise SystemExit(0 if all(c == 0 for _, c in outcomes) else 1)


if __name__ == "__main__":
    main()
