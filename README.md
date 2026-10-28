# splunk_saml_migration

Copy SAML users, their roles, role definitions and SAML group mappings from one Splunk Cloud stack (**source**) to another (**target**). All deployment details live in `config.json`. Nothing is hard-coded.

Requires Python 3.8+ (`pip install -r requirements.txt`). The AWS CLI is needed only if tokens come from SSM.

## Quick start

```bash
cp config.example.json config.json   # edit: stack names + credentials
python migrate.py                    # probe → fetch → roles → groups → users (DRY RUN)
python migrate.py --apply            # same, for real
```

**Every script is a dry run unless you pass `--apply`.** A dry run makes no write calls and produces the same report the real run would.

## Scripts

| Script | Does | Writes to |
|---|---|---|
| `probe.py` | Checks endpoints, token identity and expiry, and that the source and target are different instances | – |
| `fetch.py` | Snapshots both stacks into `data/` | local only |
| `sync_roles.py` | Copies role definitions (ACS) | target roles |
| `sync_saml_groups.py` | Copies SAML group → role mappings (REST) | target groups |
| `sync_users.py` | Creates or extends per-user SAML role mappings (REST) | target user map |
| `rollback_users.py` | Undoes a `sync_users.py --apply` run from its journal | target user map |
| `migrate.py` | Runs probe → fetch → the three syncs in order, and stops on the first failure | as above |

Shared code is in `lib/`. Snapshots go to `data/` and reports and journals to `results/`. Both are git-ignored.

**Order matters:** a role missing on the target can't be granted. Groups go before users so roles a user already gets through a group aren't rewritten.

## Configuration

Only the keys you change need to be present. Defaults are in [lib/config.py](lib/config.py), and every key is documented in [config.example.json](config.example.json).

```json
{ "stacks": {
    "source": { "label": "old", "stack": "acme-old", "ssm_key": "/splunk/old-token" },
    "target": { "label": "new", "stack": "acme-new", "ssm_key": "/splunk/new-token" } } }
```

`"stack": "acme"` derives `https://admin.splunk.com/acme/adminconfig/v2` and `https://acme.splunkcloud.com:8089`. Set `acs_base` / `rest_base` only for non-standard URLs.

**Credentials**, first match wins: `--source-token`/`--target-token` → `$SPLUNK_SOURCE_TOKEN`/`$SPLUNK_TARGET_TOKEN` → `"token"` in config → `"ssm_key"` through the AWS CLI. If you put a token in `config.json`, don't commit it. Each report records which source was used.

| Key | Default | Why |
|---|---|---|
| `roles.protected` | `admin, sc_admin, power, user, can_delete` | ACS refuses to edit these, so they're skipped |
| `roles.baseline` | `user` | Always included, so no user ends up with no roles |
| `write.settle` | `20` s | Wait before the bulk verification re-read |
| `write.create_attempts` | `15` | Retries on `409` while the cluster catches up |
| `users.require_saml_mapping_on_source` | `true` | Skips local and service accounts |
| `users.exclude_users` / `exclude_patterns` | `[]` | Exact names and `fnmatch` patterns to leave alone |

## What `sync_users.py` does

| Source user is… | Action |
|---|---|
| not on the target | `CREATE` the mapping with their source roles |
| on the target but missing roles | `ADD` the missing roles |
| on the target with every role | nothing (`in_sync`) |
| holding a role the target doesn't have | that role is dropped and reported |
| without a SAML mapping | skipped (local or service account) |

Roles are only **added**, never removed. Users that exist only on the target aren't touched. "Missing" is judged against **effective** roles, which include roles granted through groups.

```bash
python sync_users.py --users alice@x.edu,bob@x.edu   # just these users
python sync_users.py --limit 5 --apply               # canary run on 5 users
python sync_users.py --source-roles mapping          # ignore group-derived roles
```

### Rollback

Each `--apply` run writes `results/user_journal_<ts>.jsonl` *before* each change.

```bash
python rollback_users.py --journal user_journal_<ts>.jsonl --verify   # read-only state check
python rollback_users.py --journal user_journal_<ts>.jsonl --apply
```

Roles and groups have no journal. Their "before" state is `data/target_roles.json` and `data/target_groups.json`, so copy those aside before `--apply` if you might need them.

## Offline testing

`_offline_test/` is a separate config with its own `data/` and `results/`. Fetch once, then run dry runs with no network:

```bash
cp _offline_test/config.example.json _offline_test/config.json
python fetch.py   --config _offline_test/config.json             # once, needs credentials
python migrate.py --config _offline_test/config.json --skip-probe --skip-fetch
```

## Further reading

- [docs/API_NOTES.md](docs/API_NOTES.md): the Splunk API behaviour this code works around (non-atomic SAML updates, eventual consistency, ACS paging limits, and more), plus a summary of the safety checks.

`config.json`, `data/` and `results/` hold real usernames, roles and possibly tokens, and are git-ignored. Keep it that way in any fork.
