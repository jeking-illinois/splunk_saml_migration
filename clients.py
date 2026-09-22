#!/usr/bin/env python3
"""
ACS and REST clients for a Splunk Cloud stack.

Two APIs are needed because neither covers the job on its own:

  ACS   https://admin.splunk.com/{stack}/adminconfig/v2
        reads and writes ROLES; reads users, capabilities, apps, indexes.
        JSON bodies. Cannot write SAML user role mappings - PATCH /users/{name}
        comes back 403 insufficient permission(s) with a normal admin token.

  REST  https://{stack}.splunkcloud.com:8089
        the only way to write SAML group and SAML user role mappings.
        Bodies are form-urlencoded, `roles` is a REPEATED key (roles=a&roles=b),
        and output_mode=json is required or responses are Atom XML.

Both authenticate with the same Splunk-issued JWT (kid: splunk.secret) as a
bearer token.
"""

import base64
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def token_expiry(token):
    """(expiry_datetime_or_None, is_expired). Decodes the JWT payload without
    verifying the signature - this is for reporting, not for trust."""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None, False
    seg = parts[1]
    try:
        payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        return None, False
    exp = payload.get("exp")
    if not exp:
        return None, False
    try:
        when = datetime.fromtimestamp(int(exp), tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None, False
    return when, when < datetime.now(timezone.utc)


def token_identity(token):
    """The 'sub' claim, or '' - who the token says it is."""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return ""
    seg = parts[1]
    try:
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))).get("sub", "")
    except Exception:
        return ""


class ApiError(Exception):
    """A non-2xx response. Carries the status and the raw body."""

    def __init__(self, status, body):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body}")

    @property
    def code(self):
        """The ACS machine-readable code, e.g. 'ROLE_ALREADY_EXISTS', if present."""
        try:
            return json.loads(self.body).get("code", "")
        except Exception:
            return ""

    @property
    def message(self):
        """Human-readable reason from an ACS JSON, REST JSON, or Atom XML body."""
        body = self.body or ""
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            if "<msg" in body:  # Atom: <msg type="ERROR">...</msg>
                start = body.find(">", body.find("<msg")) + 1
                end = body.find("</msg>", start)
                if start > 0 and end > start:
                    return body[start:end].strip()[:400]
            return body.strip()[:400]
        if isinstance(data, dict):
            for key in ("message", "error", "detail"):
                if isinstance(data.get(key), str):
                    return data[key][:400]
            msgs = data.get("messages")
            if isinstance(msgs, list) and msgs:
                return "; ".join(str(m.get("text", m)) for m in msgs)[:400]
        return json.dumps(data)[:400]


class _Base:
    def __init__(self, cfg, role):
        self.cfg = cfg
        self.role = role
        self.stack = cfg.stack(role)
        self.label = self.stack.label
        self.ctx = ssl.create_default_context()

    @property
    def token(self):
        return self.stack.token

    def _send(self, method, url, data=None, headers=None, json_body=False):
        last_err = None
        for attempt in range(self.cfg.max_retries):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Authorization", f"Bearer {self.token}")
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            if data is not None:
                req.add_header("Content-Type", "application/json" if json_body
                               else "application/x-www-form-urlencoded")
            try:
                resp = urllib.request.urlopen(req, context=self.ctx,
                                              timeout=self.cfg.timeout)
                raw = resp.read().decode("utf-8")
                if not raw.strip():
                    return {}
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return {"_raw": raw}
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                # Rate limit or transient server error -> back off and retry.
                if e.code == 429 or 500 <= e.code < 600:
                    last_err = ApiError(e.code, body)
                    time.sleep(2 ** attempt)
                    continue
                raise ApiError(e.code, body)
            except (TimeoutError, urllib.error.URLError) as e:
                last_err = ApiError(0, f"{type(e).__name__}: {e}")
                time.sleep(2 ** attempt)
                continue
        raise last_err


class AcsClient(_Base):
    """ACS. Reads everything; writes roles."""

    # Required whenever fsh_manage appears in a role's capabilities or a user's grants.
    HEADERS = {"Federated-Search-Manage-Ack": "Y"}

    def _request(self, method, path, body=None, params=None):
        url = self.stack.acs_base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        return self._send(method, url, data=data, headers=self.HEADERS, json_body=True)

    def _paged(self, path, key):
        """ACS pages with count<=100 + offset and returns no nextLink, so read
        until a short page comes back."""
        size = self.cfg.acs_page_size
        out, offset = [], 0
        while True:
            payload = self._request("GET", path, params={"count": size, "offset": offset})
            items = payload.get(key, []) if isinstance(payload, dict) else payload
            if not items:
                break
            out.extend(items)
            offset += len(items)
            if len(items) < size:
                break
        return out

    # ---- roles -------------------------------------------------------------
    def list_roles(self):
        return self._paged("/roles", "roles")

    def create_role(self, payload):
        return self._request("POST", "/roles", body=payload)

    def update_role(self, name, payload):
        return self._request("PATCH", f"/roles/{urllib.parse.quote(name, safe='')}",
                             body=payload)

    # ---- users and reference data -------------------------------------------
    def list_users(self):
        return self._paged("/users", "users")

    def capabilities(self):
        """-> (systemCapabilities, grantableCapabilities) as sets."""
        d = self._request("GET", "/capabilities")
        return set(d.get("systemCapabilities", [])), set(d.get("grantableCapabilities", []))

    def app_names(self):
        return {a.get("name") for a in self._paged("/apps/victoria", "apps") if a.get("name")}

    def index_names(self):
        return {i.get("name") for i in self._paged("/indexes", "indexes")
                if isinstance(i, dict) and i.get("name")}


class RestClient(_Base):
    """Splunk management-port REST API on :8089. Writes SAML mappings."""

    USER_MAP = "/services/admin/SAML-user-role-map"
    GROUPS = "/services/admin/SAML-groups"

    def _url(self, path, params=None):
        query = list(params or [])
        if not any(k == "output_mode" for k, _ in query):
            query.append(("output_mode", "json"))
        return f"{self.stack.rest_base}{path}?" + urllib.parse.urlencode(query)

    def _request(self, method, path, fields=None, params=None):
        data = urllib.parse.urlencode(fields).encode("utf-8") if fields else None
        return self._send(method, self._url(path, params), data=data)

    def _paged(self, path):
        size = self.cfg.rest_page_size
        out, offset = [], 0
        while True:
            payload = self._request("GET", path,
                                    params=[("count", size), ("offset", offset)])
            entries = (payload or {}).get("entry") or []
            if not entries:
                break
            out.extend(entries)
            total = ((payload or {}).get("paging") or {}).get("total")
            offset += len(entries)
            if len(entries) < size or (total is not None and offset >= total):
                break
        return out

    @staticmethod
    def _roles_of(entry):
        roles = (entry.get("content") or {}).get("roles") or []
        return [roles] if isinstance(roles, str) else list(roles)

    # ---- SAML user -> role map ---------------------------------------------

    def user_role_map(self):
        """{username: [roles]}.

        This is the per-user mapping that writes land on. It is NOT the same as a
        user's effective roles - a SAML user can also inherit roles from SAML
        *group* mappings, which never appear here.
        """
        return {e.get("name", ""): self._roles_of(e) for e in self._paged(self.USER_MAP)}

    def get_user(self, name):
        """Mapped roles for one user, or None if there is no mapping."""
        payload = self._request("GET", f"{self.USER_MAP}/{urllib.parse.quote(name, safe='')}")
        entries = (payload or {}).get("entry") or []
        return self._roles_of(entries[0]) if entries else None

    def create_user(self, name, roles):
        """POST to the collection. 409s if the user already has a mapping."""
        fields = [("name", name)] + [("roles", r) for r in roles]
        return self._request("POST", self.USER_MAP, fields=fields)

    def delete_user(self, name):
        return self._request("DELETE", f"{self.USER_MAP}/{urllib.parse.quote(name, safe='')}")

    def replace_user_roles(self, name, desired, exists=None):
        """Set a SAML user's mapped roles to exactly `desired`.

        This endpoint has NO edit action - POSTing to an entry returns:
            404 Invalid action for this internal handler
                (handler: SAML-user-role-map, supported: create|list|remove|new)
        and creating over an existing entry returns 409. So an existing mapping
        must be REMOVED and re-CREATED.

        Neither step propagates across the search head cluster synchronously.
        Measured: a CREATE issued immediately after a successful DELETE 409s for
        ~1.5s before it takes. So the create is retried on 409 specifically - a
        409 in that window means stale cluster state, not a real conflict.

        Deliberately does NOT verify by reading back: for a few seconds after a
        write a GET can return '400 not found' immediately after a GET that
        returned the new value, so per-user verification produces false alarms.
        Verification is done in bulk once the run settles, which is both
        authoritative and one call instead of hundreds.

        Pass `exists` from a snapshot to skip the existence probe.

        Returns (ok, detail, calls). The caller MUST journal the prior roles
        BEFORE calling this: between the remove and the create the user has no
        mapping at all, so a hard failure here can leave them with none.
        """
        want = sorted(set(desired))
        calls = 0

        if exists is None:
            try:
                exists = self.get_user(name) is not None
                calls += 1
            except ApiError as e:
                calls += 1
                # A missing mapping answers 400 "Unable to find a role mapping
                # for user=X", not 404.
                if e.status in (400, 404):
                    exists = False
                else:
                    return False, f"read failed: {e.status} {e.message}", calls

        if exists:
            try:
                self.delete_user(name)
                calls += 1
            except ApiError as e:
                calls += 1
                # Already gone is fine. Anything else means we must not create,
                # or we would be writing over state we do not understand.
                if e.status not in (400, 404):
                    return False, f"remove failed: {e.status} {e.message}", calls

        last = ""
        for attempt in range(self.cfg.create_attempts):
            try:
                self.create_user(name, want)
                calls += 1
                return True, f"created (attempt {attempt + 1})", calls
            except ApiError as e:
                calls += 1
                last = f"{e.status} {e.message}"
                if e.status != 409:
                    return False, f"create failed: {last}", calls
                time.sleep(self.cfg.create_poll)

        return False, f"create still 409 after {self.cfg.create_attempts} tries: {last}", calls

    # ---- SAML groups --------------------------------------------------------

    def group_map(self):
        """{group: [roles]} - group mappings grant roles without touching the
        per-user map, so they are needed to explain effective roles."""
        return {e.get("name", ""): sorted(self._roles_of(e))
                for e in self._paged(self.GROUPS)}

    def create_group(self, name, roles):
        fields = [("name", name)] + [("roles", r) for r in roles]
        return self._request("POST", self.GROUPS, fields=fields)

    def update_group(self, name, roles):
        """Unlike the user map, groups DO support edit. `roles` overwrites."""
        path = f"{self.GROUPS}/{urllib.parse.quote(name, safe='')}"
        # A group with no roles still needs the key present, or Splunk 400s.
        fields = [("roles", r) for r in roles] or [("roles", "")]
        return self._request("POST", path, fields=fields)

    def role_names(self):
        """Role names on this search head, straight from REST (validates mappings)."""
        payload = self._request("GET", "/services/authorization/roles",
                                params=[("count", 0)])
        return {e.get("name") for e in (payload.get("entry") or []) if e.get("name")}

    def server_info(self):
        """serverName / guid / version - proves which instance you reached."""
        payload = self._request("GET", "/services/server/info")
        c = ((payload.get("entry") or [{}])[0].get("content") or {})
        return {"serverName": c.get("serverName", ""), "guid": c.get("guid", ""),
                "version": c.get("version", ""), "instance_type": c.get("instance_type", ""),
                "server_roles": c.get("server_roles") or []}

    def current_context(self):
        """Who the token authenticates as, according to the stack itself."""
        payload = self._request("GET", "/services/authentication/current-context")
        c = ((payload.get("entry") or [{}])[0].get("content") or {})
        return {"username": c.get("username", ""), "roles": c.get("roles") or []}
