#!/usr/bin/env python3
"""
Configuration loading and credential resolution.

Everything deployment-specific lives in config.json; nothing in this package
hard-codes a hostname, a token, or an AWS profile. See config.example.json for a
documented template.

    from config import load_config
    cfg = load_config(args.config)
    cfg.source.label, cfg.target.acs_base, cfg.baseline_role, ...

Credentials resolve in this order, first hit wins:

    1. --source-token / --target-token on the command line
    2. $SPLUNK_SOURCE_TOKEN / $SPLUNK_TARGET_TOKEN
    3. "token" in config.json (plain text)
    4. "ssm_key" in config.json, read via the AWS CLI   <- the default

Anything above step 4 means AWS is never invoked, so this runs fine on a machine
with no AWS credentials at all. Step 3 puts a live token on disk in plain text -
config.json should not be committed if you use it.

A stack can be described either fully (acs_base + rest_base) or by just its
Splunk Cloud stack name, in which case the standard URLs are derived:

    "stack": "acme"  ->  https://admin.splunk.com/acme/adminconfig/v2
                         https://acme.splunkcloud.com:8089
"""

import copy
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(HERE, "config.json")

# Every setting with a sane default. config.json is merged over this, key by key,
# so a partial config file is valid - you only write down what you're changing.
DEFAULTS = {
    "aws": {
        "profile": "",
        "region": "us-east-2",
    },
    "stacks": {
        "source": {"label": "source", "stack": "", "acs_base": "", "rest_base": "",
                   "ssm_key": "", "token": ""},
        "target": {"label": "target", "stack": "", "acs_base": "", "rest_base": "",
                   "ssm_key": "", "token": ""},
    },
    "roles": {
        # ACS refuses to edit or delete these built-ins; they are skipped entirely.
        "protected": ["admin", "sc_admin", "power", "user", "can_delete"],
        # The role every SAML user gets for free. Always included in a write so a
        # user can never end up with an empty role list.
        "baseline": "user",
    },
    "http": {
        "timeout": 180,
        "max_retries": 5,
        # ACS hard-caps this: 400 invalid 'count' value: N. Maximum value is 100.
        "acs_page_size": 100,
        "rest_page_size": 250,
    },
    "write": {
        "sleep": 0.1,
        # Seconds to wait after a run before the bulk verification re-read. Search
        # head clusters propagate writes asynchronously.
        "settle": 20,
        # SAML-user-role-map has no edit action, so an update is remove-then-create,
        # and the create 409s for ~1.5s while the cluster catches up.
        "create_attempts": 15,
        "create_poll": 0.4,
    },
    "users": {
        # Users with no SAML role mapping on the source are local/service accounts
        # (crowdstrike_*, phantom*, sa-*). Writing a SAML mapping for them would
        # invent one, so they are skipped unless you say otherwise.
        "require_saml_mapping_on_source": True,
        "exclude_users": [],
        "exclude_patterns": [],
    },
    "paths": {
        "data_dir": "data",
        "results_dir": "results",
    },
}


class ConfigError(Exception):
    pass


def _merge(base, over):
    """Recursive dict merge; `over` wins. Lists replace rather than append."""
    out = copy.deepcopy(base)
    for key, value in (over or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _ssm_token(ssm_key, profile, region):
    """Read a token out of AWS SSM Parameter Store via the CLI."""
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"  # keep git-bash from mangling the /path/... name
    cmd = ["aws", "ssm", "get-parameter", "--name", ssm_key, "--with-decryption",
           "--query", "Parameter.Value", "--output", "text"]
    if profile:
        cmd += ["--profile", profile]
    if region:
        cmd += ["--region", region]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    except FileNotFoundError:
        raise ConfigError(
            f"cannot read {ssm_key}: the 'aws' CLI is not on PATH.\n"
            f"    Either install it, or avoid AWS entirely by setting a plain "
            f"'token' in config.json or passing --source-token/--target-token.")
    except subprocess.TimeoutExpired:
        raise ConfigError(f"timed out reading {ssm_key} from SSM")
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        raise ConfigError(f"reading {ssm_key} from SSM failed: "
                          f"{detail[-1] if detail else 'unknown error'}")
    token = result.stdout.strip()
    if not token:
        raise ConfigError(f"SSM returned an empty value for {ssm_key}")
    return token


class Stack:
    """One end of the migration: source or target."""

    def __init__(self, role, raw, aws):
        self.role = role                      # "source" or "target"
        self.label = raw.get("label") or role
        self.ssm_key = raw.get("ssm_key") or ""
        self._plain_token = raw.get("token") or ""
        self._aws = aws
        self._token = None

        name = (raw.get("stack") or "").strip()
        self.acs_base = (raw.get("acs_base") or "").rstrip("/")
        self.rest_base = (raw.get("rest_base") or "").rstrip("/")
        if name:
            # Derive the standard Splunk Cloud URLs from the stack name.
            self.acs_base = self.acs_base or \
                f"https://admin.splunk.com/{name}/adminconfig/v2"
            self.rest_base = self.rest_base or f"https://{name}.splunkcloud.com:8089"

        if not self.acs_base or not self.rest_base:
            raise ConfigError(
                f"stacks.{role} needs either \"stack\": \"<name>\" or both "
                f"\"acs_base\" and \"rest_base\"")

    @property
    def env_var(self):
        return f"SPLUNK_{self.role.upper()}_TOKEN"

    def set_token(self, token):
        """Override from the command line."""
        if token:
            self._token = token

    @property
    def token_source(self):
        """Where the token came from - printed in reports so it's never a mystery."""
        if self._token:
            return "explicit (--token or env)"
        if self._plain_token:
            return "config.json plain text"
        return f"AWS SSM {self.ssm_key}" if self.ssm_key else "(none)"

    @property
    def token(self):
        """Resolved lazily so a dry run never needs credentials it won't use."""
        if self._token:
            return self._token
        env = os.environ.get(self.env_var)
        if env:
            self._token = env.strip()
            return self._token
        if self._plain_token:
            self._token = self._plain_token
            return self._token
        if self.ssm_key:
            self._token = _ssm_token(self.ssm_key, self._aws.get("profile"),
                                     self._aws.get("region"))
            return self._token
        raise ConfigError(
            f"no credential for stacks.{self.role}. Set one of: "
            f"--{self.role}-token, ${self.env_var}, \"token\", or \"ssm_key\".")


class Config:
    def __init__(self, raw, path):
        self.path = path
        self.raw = raw

        aws = raw["aws"]
        self.aws_profile = aws.get("profile") or ""
        self.aws_region = aws.get("region") or ""

        self.source = Stack("source", raw["stacks"]["source"], aws)
        self.target = Stack("target", raw["stacks"]["target"], aws)

        self.protected_roles = set(raw["roles"]["protected"])
        self.baseline_role = raw["roles"]["baseline"]

        http = raw["http"]
        self.timeout = http["timeout"]
        self.max_retries = http["max_retries"]
        self.acs_page_size = min(int(http["acs_page_size"]), 100)  # ACS hard limit
        self.rest_page_size = http["rest_page_size"]

        write = raw["write"]
        self.sleep = write["sleep"]
        self.settle = write["settle"]
        self.create_attempts = write["create_attempts"]
        self.create_poll = write["create_poll"]

        users = raw["users"]
        self.require_saml_mapping_on_source = users["require_saml_mapping_on_source"]
        self.exclude_users = set(users["exclude_users"])
        self.exclude_patterns = list(users["exclude_patterns"])

        base = os.path.dirname(os.path.abspath(path)) if path else HERE
        self.data_dir = self._abs(base, raw["paths"]["data_dir"])
        self.results_dir = self._abs(base, raw["paths"]["results_dir"])

    @staticmethod
    def _abs(base, value):
        return value if os.path.isabs(value) else os.path.join(base, value)

    def stack(self, role):
        return self.source if role == "source" else self.target

    def excluded(self, user):
        """Is this username filtered out by config?"""
        import fnmatch
        if user in self.exclude_users:
            return True
        return any(fnmatch.fnmatchcase(user, p) for p in self.exclude_patterns)

    def results_path(self, filename):
        os.makedirs(self.results_dir, exist_ok=True)
        return os.path.join(self.results_dir, filename)

    def data_path(self, filename):
        os.makedirs(self.data_dir, exist_ok=True)
        return os.path.join(self.data_dir, filename)


def load_config(path=None):
    path = path or DEFAULT_CONFIG_PATH
    if not os.path.exists(path):
        print(f"ERROR: config not found: {path}\n"
              f"       Copy config.example.json to config.json and edit it.")
        sys.exit(2)
    try:
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: {path} is not valid JSON: {e}")
        sys.exit(2)
    try:
        return Config(_merge(DEFAULTS, user), path)
    except ConfigError as e:
        print(f"ERROR in {path}: {e}")
        sys.exit(2)


def add_common_args(ap):
    """CLI flags every script in this package shares."""
    ap.add_argument("--config", help="path to config.json (default: alongside these scripts)")
    ap.add_argument("--source-token", help="source stack token; skips AWS entirely")
    ap.add_argument("--target-token", help="target stack token; skips AWS entirely")
    ap.add_argument("--apply", action="store_true",
                    help="actually write (default is a dry run that changes nothing)")
    ap.add_argument("--limit", type=int, help="only process the first N items")
    ap.add_argument("--sleep", type=float, help="seconds between write calls")
    ap.add_argument("--out", help="output .xlsx filename (written into the results dir)")
    return ap


def configure(args):
    """Load config and apply the token/sleep overrides from parsed args."""
    cfg = load_config(getattr(args, "config", None))
    cfg.source.set_token(getattr(args, "source_token", None))
    cfg.target.set_token(getattr(args, "target_token", None))
    if getattr(args, "sleep", None) is not None:
        cfg.sleep = args.sleep
    return cfg
