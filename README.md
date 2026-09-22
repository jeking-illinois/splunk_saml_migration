# splunk_saml_migration

Migrate SAML users, their roles, role definitions and SAML group mappings from one
Splunk Cloud stack to another.

Everything deployment-specific lives in `config.json`. No hostname, token, AWS
profile or role name is hard-coded, so the same scripts work for any
source → target pair. "Source" is the stack you are copying **from**; "target" is
the stack you are copying **to**.

Generalized from the `orphan_manager` and `splunk_roles` sub-projects after they
were used to migrate 868 users between two search head clusters. Everything those
scripts learned the hard way about the Splunk APIs is preserved here, mostly as
comments explaining why a line exists.

---

## Quick start

```bash
cp config.example.json config.json    # then edit it
python probe.py                       # are both stacks reachable?
python fetch.py                       # snapshot both stacks
python sync_roles.py                  # DRY RUN - review the report
python sync_roles.py --apply
python sync_saml_groups.py            # DRY RUN
python sync_saml_groups.py --apply
python sync_users.py                  # DRY RUN
python sync_users.py --apply
```

Or run the lot in the right order:

```bash
python migrate.py                     # probe + fetch + all three syncs, DRY RUN
python migrate.py --apply
```

**Every script is a dry run unless you pass `--apply`.** A dry run makes no write
calls at all and produces the same report the real run will, so the plan you
review is the plan that executes.

Requires Python 3.8+ and `openpyxl`. The AWS CLI is needed only if you store
tokens in SSM, which is the default.

---

## The order matters

1. **`sync_roles.py`** – a role that does not exist on the target cannot be
   granted to anyone, so any role missing here becomes a dropped grant in steps 2
   and 3.
2. **`sync_saml_groups.py`** – group mappings grant roles without touching any
   user. Doing them first means step 3 sees those roles as already granted and
   skips writes it does not need.
3. **`sync_users.py`** – per-user mappings, for whatever the groups do not cover.

`migrate.py` enforces this order and stops on the first failure.

---

## Scripts

| Script | What it does | Writes to |
|---|---|---|
| `probe.py` | Tests all four API endpoints, token identity and expiry, and that the two stacks are genuinely different instances | nothing |
| `fetch.py` | Snapshots both stacks into `data/` | `data/` |
| `sync_roles.py` | Copies role definitions to the target via ACS | target roles |
| `sync_saml_groups.py` | Copies SAML group → role mappings via REST | target SAML groups |
| `sync_users.py` | Creates/extends per-user SAML role mappings via REST | target SAML user map |
| `rollback_users.py` | Undoes a `sync_users.py --apply` run from its journal | target SAML user map |
| `migrate.py` | Runs the stages above in order | as above |

Supporting modules: `config.py` (config + credentials), `clients.py` (ACS + REST),
`snapshots.py` (typed snapshot readers), `report.py` (Excel output).

Everything generated goes into `results/`; snapshots go into `data/`. The package
directory itself stays clean.

---

## Configuration

`config.json` sits next to the scripts, or is passed with `--config`. Only the
keys you want to change need to be present - everything else falls back to the
defaults in `config.py`, so a three-line config file is valid. See
`config.example.json` for a fully documented template.

```json
{
  "stacks": {
    "source": { "label": "acme-old", "stack": "acme-old",
                "ssm_key": "/splunk/acme-old-token" },
    "target": { "label": "acme-new", "stack": "acme-new",
                "ssm_key": "/splunk/acme-new-token" }
  }
}
```

Given `"stack": "acme"`, the standard Splunk Cloud URLs are derived:

```
ACS   https://admin.splunk.com/acme/adminconfig/v2
REST  https://acme.splunkcloud.com:8089
```

Set `acs_base` / `rest_base` explicitly only when the URLs are non-standard.

### Credentials

Resolved in this order, first hit wins:

| | Where | AWS needed? |
|---|---|---|
| 1 | `--source-token` / `--target-token` on the command line | no |
| 2 | `$SPLUNK_SOURCE_TOKEN` / `$SPLUNK_TARGET_TOKEN` | no |
| 3 | `"token"` in `config.json`, plain text | no |
| 4 | `"ssm_key"` in `config.json`, read with the AWS CLI | yes (default) |

Anything above step 4 means AWS is never invoked, so this runs fine on a machine
with no AWS credentials at all.

**If you use option 3, do not commit `config.json`** - it contains a live
credential. Every report records which of the four sources was used, so it is
never a mystery after the fact.

Tokens are resolved lazily. A dry run that never calls an API never needs a
credential for it.

### Settings worth knowing about

| Key | Default | Why it matters |
|---|---|---|
| `roles.protected` | `admin, sc_admin, power, user, can_delete` | ACS refuses to edit these built-ins; they are skipped entirely |
| `roles.baseline` | `user` | always included in a user write, so nobody can end up with an empty role list |
| `http.acs_page_size` | 100 | ACS hard-caps this; a larger value is clamped, not sent |
| `write.settle` | 20 s | how long to wait before the bulk verification re-read |
| `write.create_attempts` | 15 | 409 retries while a search head cluster converges |
| `users.require_saml_mapping_on_source` | `true` | skips local/service accounts, which have no SAML mapping to copy |
| `users.exclude_users` / `exclude_patterns` | `[]` | names and `fnmatch` globs to leave alone entirely |

---

## What `sync_users.py` does

Every SAML user on the **source** is considered, regardless of what they look like
on the target:

| Situation | Action |
|---|---|
| Not on the target | `CREATE` the mapping with their source roles |
| On the target, missing roles | `ADD` the missing roles to their existing mapping |
| On the target, has everything | `in_sync` - no call is made |
| Source role absent on the target | dropped from the payload and reported |
| No SAML mapping on the source | skipped as a local/service account |

Roles are only ever **added**. Nothing is removed, and users that exist only on
the target are never touched - they get their own report sheet.

"Missing" is judged against the user's **effective** roles on the target, not just
their per-user mapping, because a SAML group mapping grants roles without
appearing in the per-user map. Judging by the mapping alone would rewrite users
who already have everything via a group - no gain, and a real cost, because the
write is not atomic.

Useful flags:

```bash
python sync_users.py --users alice@example.edu,bob@example.edu   # just these two
python sync_users.py --limit 5 --apply                          # canary first
python sync_users.py --source-roles mapping                     # ignore group-derived roles
python sync_users.py --include-non-saml                          # local/service accounts too
```

### Undoing it

Every `--apply` run writes `results/user_journal_<timestamp>.jsonl` **before** each
mutation, so it is complete even if the run dies partway through.

```bash
python rollback_users.py --journal user_journal_20260922_101500.jsonl --verify
python rollback_users.py --journal user_journal_20260922_101500.jsonl --apply
```

`--verify` writes nothing and reports, per user, whether the live state matches
`roles_before` (the sync did not land, or has been rolled back),
`roles_intended` (it landed and is still in place), or neither. Run that first.

There is no equivalent for roles and groups. Their "before" state is the
pre-run snapshot in `data/target_roles.json` and `data/target_groups.json` - copy
those aside before `--apply` if you want the option.

---

## API facts this package is built around

These were all established against a live stack. They are the reason the code is
shaped the way it is.

**Two APIs are required.** ACS reads and writes roles; it *cannot* write SAML user
role mappings (`PATCH /users/{name}` returns `403 insufficient permission(s)` with
a normal admin token). REST on `:8089` is the only write path for SAML mappings.
A single Splunk-issued JWT (`kid: splunk.secret`) authenticates both.

**Roles and users are per-search-head and are NOT replicated** between clusters.
Each stack needs its own hostname and token. `probe.py` compares server GUIDs
because pointing both halves of the config at one instance would report complete
success while doing nothing.

**`SAML-user-role-map` has no edit action.** POSTing to an entry returns
`404 Invalid action for this internal handler (supported: create|list|remove|new)`,
and creating over an existing entry returns `409`. An update is therefore
remove-then-create, which is **not atomic**: between the two calls the user has no
mapping at all. Hence the journal is written *before* the mutation, and users who
need nothing are never written to.

**Search head clusters are eventually consistent.** A create issued straight after
a successful delete 409s for about 1.5 s. Reads are unstable for seconds after a
write - a `GET` can return `400 not found` immediately after a `GET` that returned
the new value. So the create retries on 409 specifically, there is no per-user
readback, and verification is one bulk re-read after `write.settle` seconds.

**A missing mapping answers `400`, not `404`** (`Unable to find a role mapping for
user=X`), so both are treated as "absent".

**SAML groups DO support edit** (`POST /services/admin/SAML-groups/{name}`), so a
group update is a single call with no window.

**Effective roles have two independent sources**: the per-user
`SAML-user-role-map` and SAML group → role mappings. Only the per-user map is
writable per user. `fetch.py` captures both, because the difference between them
is what says whether a user is genuinely missing roles or already getting them
from a group.

**ACS pagination**: `count` is hard-capped at 100
(`400 invalid 'count' value: N. Maximum value is 100`) and no `nextLink` is
returned, so paging is count + offset until a short page arrives.

**`Federated-Search-Manage-Ack: Y`** is required on ACS calls whenever
`fsh_manage` appears.

**Role field names differ between read and write**: `GET` nests inherited roles at
`imported.roles`, writes call the field `importedRoles`. Roles are written in
topological order so a role's parents exist first.

**Index wildcards**: `*` never matches internal `_`-prefixed indexes - `_*` is
required. ACS enforces that `srchIndexesDefault` is covered by
`srchIndexesAllowed`, so uncovered entries are dropped rather than widening
`srchIndexesAllowed`, which would grant access the source role never had.

**Excel cells cap at 32767 characters** and openpyxl raises past it. One real user
had 369 roles, so list cells are clamped to 32000 with a `...(N more)` suffix -
losing the whole report at the last step is worse than a truncated cell.

---

## Sanity checks, and where they live

Nothing here fails a whole run because of one bad record, and nothing is dropped
silently - every omission appears in a report column and a summary count.

- Dry run by default, everywhere.
- Plans are built from snapshots, not live calls, so a dry run is reproducible and
  the reviewed plan is the executed plan.
- Token expiry is checked and warned about before a long run starts.
- `probe.py` verifies all four endpoints, both identities, and distinct GUIDs.
- Roles absent on the target are dropped from a payload and reported, per grant
  and per distinct role.
- Protected built-in roles are never touched.
- Role payloads are sanitized against the target's real inventory of
  capabilities, apps and indexes before the first call - each of those is a known
  hard `400`.
- Role writes fall back progressively (`defaultApp` → `search`) and a `409` on
  create switches to `PATCH` rather than failing.
- A group whose roles all turn out to be absent on the target is not created at
  all - a group mapped to nothing is worse than no group.
- The user journal is written before each mutation, not after.
- Verification is a single bulk re-read after a settle delay, never a per-user
  readback.
- Rollback is idempotent: anything already at its `roles_before` state is skipped.
- HTTP 429 and 5xx retry with exponential backoff.

---

## Testing offline

`_offline_test/` is a sandbox config with its own `data/` and `results/`
directories, completely separate from your real one. Fill it once, and every dry
run after that exercises the full planning path with no network and no AWS -
useful for reviewing a plan, or for working on the scripts themselves:

```bash
cp _offline_test/config.example.json _offline_test/config.json
python fetch.py --config _offline_test/config.json      # once, with real credentials
python migrate.py --config _offline_test/config.json --skip-probe --skip-fetch
```

The snapshots it writes are deliberately not committed - see below.

---

## What is deliberately not in this repository

`.gitignore` excludes `config.json`, `data/` and `results/` (including the
`_offline_test/` copies), because all three contain real information about a live
Splunk estate:

| Path | Why it stays local |
|---|---|
| `config.json` | your stack names, SSM parameter paths, and - if you use credential option 3 - a live token in plain text |
| `data/` | snapshots: every username on both stacks, their roles, plus your index, app and SAML group names |
| `results/` | the Excel reports and rollback journals, which are per-user by definition |

`config.example.json` is the committed template; copy it to `config.json`, which
git will then ignore. If you fork this and add automation, keep that exclusion -
a single `fetch.py` run is enough to turn `data/` into a directory full of real
user identities.
