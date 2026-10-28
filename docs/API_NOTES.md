# Splunk API notes

Behaviour observed against live Splunk Cloud stacks. The code is shaped around these facts.

## Two APIs are required

- **ACS** reads and writes roles. It *cannot* write SAML user mappings: `PATCH /users/{name}` returns `403` with a normal admin token.
- **REST** (`:8089`) is the only write path for SAML mappings.
- One Splunk-issued JWT (`kid: splunk.secret`) authenticates both.

## Stacks are independent

Roles and users are per search head and **not replicated** between clusters. Each stack needs its own host and token. `probe.py` compares server GUIDs, because pointing source and target at the same instance would report success while doing nothing.

## SAML-user-role-map

- **No edit action.** POST to an entry → `404 Invalid action ... (supported: create|list|remove|new)`. Create over an existing entry → `409`.
- An update is therefore **remove + create, which is not atomic**: between the two calls the user has no mapping. The journal is written before each mutation, and users who need nothing are never written.
- A missing mapping answers **`400`, not `404`** (`Unable to find a role mapping for user=X`). Both are treated as absent.

## SAML groups

Support edit (`POST /services/admin/SAML-groups/{name}`), so a group update is one call with no gap.

## Effective roles have two sources

The per-user map and SAML group → role mappings. Only the per-user map is writable per user. `fetch.py` captures both, because the difference is what tells you whether a user is really missing roles or already gets them from a group.

## Search head clusters are eventually consistent

- A create straight after a delete returns `409` for about 1.5 s.
- Reads are unstable for seconds after a write. A `GET` can return `400 not found` right after one that returned the new value.
- So creates retry on `409`, there is no per-user readback, and verification is one bulk re-read after `write.settle` seconds.

## ACS details

- **Pagination:** `count` is capped at 100 (`400 invalid 'count' value`), and no `nextLink` is returned. Page with count + offset until a short page comes back.
- **`Federated-Search-Manage-Ack: Y`** is required whenever `fsh_manage` appears.
- **Field names differ between read and write:** `GET` nests inherited roles at `imported.roles`, writes use `importedRoles`. Roles are written in topological order so parents exist first.
- **Index wildcards:** `*` never matches `_`-prefixed indexes, so `_*` is needed. ACS requires `srchIndexesDefault` ⊆ `srchIndexesAllowed`. Uncovered defaults are dropped rather than widening `srchIndexesAllowed`, which would grant access the source never had.
- Unknown capabilities, apps or indexes in a role payload are a hard `400`, so payloads are cleaned against the target's inventory first.

## Excel

Cells cap at 32,767 characters, and openpyxl raises an error past that. One real user had 369 roles, so list cells are clamped to 32,000 with a `...(N more)` suffix.

## Safety checks, summarized

- Dry run by default. Plans are built from snapshots, so the reviewed plan is the plan that runs.
- One bad record never fails a run, and nothing is dropped silently: every omission is a report column and a summary count.
- Token expiry is checked before a long run.
- Protected built-in roles are never touched.
- Role writes fall back progressively (`defaultApp` → `search`), and a `409` on create switches to `PATCH`.
- A group whose roles are all missing on the target is not created.
- Rollback is idempotent.
- HTTP 429 and 5xx responses retry with exponential backoff.
