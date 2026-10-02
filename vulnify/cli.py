"""Vulnify CLI. Installed by the vulnify[cli] extra (PyYAML and jsonschema).

Commands, flags, messages, and exit codes match the npm ``vulnify`` CLI.
The core package does not import this module.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from importlib.resources import files
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .client import DEFAULT_BASE_URL, Vulnify, VulnifyError

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_REVIEW = 2
EXIT_BLOCK = 3
EXIT_UNSUPPORTED = 4
EXIT_AUTH = 5

UNSUPPORTED_MESSAGE = "This Vulnify server does not support policies as code yet"
LOGIN_PROBE_ID = "00000000-0000-4000-8000-000000000000"

VALUE_FLAGS = {"api-key", "base-url", "agent", "action", "resource", "destination", "records", "out"}
BOOL_FLAGS = {"prune", "dry-run", "local", "sensitive", "version"}
EVENT_ACTIONS = {"READ_DATA", "WRITE_DATA", "DELETE_DATA", "EXPORT_DATA", "SEND_EMAIL"}
DESTINATIONS = {"INTERNAL", "EXTERNAL_EMAIL", "EXTERNAL_API"}
SPEC_KEYS = ("description", "enabled", "action", "resource", "condition", "decision", "mode", "approverRoles")

EXAMPLE_POLICY_YAML = """\
# Policies in this tree are safe to commit.
# API keys are not stored here. `vulnify login` writes ~/.config/vulnify/credentials.json (mode 0600).
#
# spec.action is the action family (ANY, READ, WRITE, DELETE, EXPORT).
# A specific event action such as EXPORT_DATA belongs in condition.action.
# spec.resource is a resource type. The event resource name belongs in a PolicyTest input.
# condition.minRecords means recordsAffected >= that number. More than 1000 records is 1001.
apiVersion: vulnify.io/v1
kind: Policy
metadata:
  name: block-bulk-customer-export
spec:
  description: Block exports of more than 1000 customer records
  enabled: true
  action: EXPORT
  resource: CUSTOMER_PII
  condition:
    minRecords: 1001
  decision: BLOCK
  mode: ENFORCE
  approverRoles:
    - OWNER
    - ADMIN
"""

EXAMPLE_TEST_YAML = """\
# input.action is the event action. input.resource is the resource name.
# expect.policy is the metadata.name of a Policy document.
apiVersion: vulnify.io/v1
kind: PolicyTest
metadata:
  name: export-rules
cases:
  - name: bulk export is blocked
    input:
      agent: support-bot
      action: EXPORT_DATA
      resource: customers-db
      recordsAffected: 5000
    expect:
      decision: BLOCK
      policy: block-bulk-customer-export
"""

GITIGNORE_HINT = """\
# Policies and tests in this directory are safe to commit.
# Do not commit API keys. `vulnify login` writes ~/.config/vulnify/credentials.json
# with mode 0600, outside this repository.
"""

GITIGNORE_STDOUT = (
    "Do not commit API keys. vulnify login stores them in ~/.config/vulnify/credentials.json "
    "(mode 0600), outside this repository. A hint was written to vulnify/.gitignore.\n"
)

HELP = f"""\
vulnify — policies as code and one-off decisions

Usage:
  vulnify init
  vulnify login [--api-key <key>] [--base-url <url>]
  vulnify check --agent <name> --action <action> --resource <name> [--destination <dest>] [--records <n>] [--sensitive]
  vulnify policies validate [path]
  vulnify policies pull [--out <dir>]
  vulnify policies apply [path] [--prune] [--dry-run]
  vulnify test [path] [--local]

Every command accepts --json. There is no telemetry.

Credentials:
  ~/.config/vulnify/credentials.json (mode 0600)
  VULNIFY_API_KEY and VULNIFY_BASE_URL take precedence.
  Default base URL: {DEFAULT_BASE_URL}

Exit codes:
  0  ok, or ALLOW from check
  1  test failure or validation error
  2  REVIEW (check only)
  3  BLOCK (check only)
  4  this server has no policies-as-code API
  5  auth error

policies pull, apply, and test print "{UNSUPPORTED_MESSAGE}" and exit 4 when the server responds 404.
"""


class CliError(Exception):
    def __init__(self, message: str, exit_code: int, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.details = details


def console_main() -> None:
    raise SystemExit(main())


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    stdout = sys.stdout
    stderr = sys.stderr
    try:
        parsed = _parse_argv(args)
        return _dispatch(parsed, stdout.write, stderr.write)
    except CliError as err:
        _fail(parsed_json(args), err, stdout.write)
        return err.exit_code


def parsed_json(argv: Sequence[str]) -> bool:
    return "--json" in argv


def _fail(json_mode: bool, err: CliError, write: Any) -> None:
    payload: Dict[str, Any] = {"ok": False, "exitCode": err.exit_code, "error": err.message}
    if err.details is not None:
        payload["details"] = err.details
    _emit(json_mode, payload, err.message, write)


def _emit(json_mode: bool, data: Any, text: str, write: Any) -> None:
    if json_mode:
        write(json.dumps(data, indent=2) + "\n")
        return
    write(text if text.endswith("\n") else text + "\n")


def _parse_argv(argv: Sequence[str]) -> Dict[str, Any]:
    flags: Dict[str, Any] = {}
    positionals: List[str] = []
    json_mode = False
    help_flag = False
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            positionals.extend(argv[index + 1 :])
            break
        if arg == "--json":
            json_mode = True
            index += 1
            continue
        if arg in ("--help", "-h"):
            help_flag = True
            index += 1
            continue
        if not arg.startswith("--"):
            positionals.append(arg)
            index += 1
            continue
        eq = arg.find("=")
        name = arg[2:] if eq == -1 else arg[2:eq]
        if name in VALUE_FLAGS:
            if eq == -1:
                index += 1
                if index >= len(argv) or argv[index].startswith("--"):
                    raise CliError(f"Missing value for --{name}", EXIT_FAILURE)
                value = argv[index]
            else:
                value = arg[eq + 1 :]
            flags[name] = value
            index += 1
            continue
        if name in BOOL_FLAGS:
            if eq != -1:
                raise CliError(f"--{name} does not take a value", EXIT_FAILURE)
            flags[name] = True
            index += 1
            continue
        raise CliError(f"Unknown flag --{name}", EXIT_FAILURE)
    return {"json": json_mode, "help": help_flag, "positionals": positionals, "flags": flags}


def _dispatch(parsed: Dict[str, Any], stdout: Any, stderr: Any) -> int:
    json_mode = bool(parsed["json"])
    flags = parsed["flags"]
    positionals = list(parsed["positionals"])
    command = positionals[0] if positionals else None
    sub = positionals[1] if len(positionals) > 1 else None
    rest = positionals[2:]

    def emit(data: Any, text: str) -> None:
        _emit(json_mode, data, text, stdout)

    if flags.get("version") and not command:
        version = _package_version()
        emit({"ok": True, "exitCode": 0, "version": version}, version + "\n")
        return EXIT_OK
    if not command:
        emit({"ok": True, "exitCode": 0, "help": HELP}, HELP)
        return EXIT_OK if parsed["help"] else EXIT_FAILURE
    if parsed["help"]:
        emit({"ok": True, "exitCode": 0, "help": HELP}, HELP)
        return EXIT_OK
    if rest and command != "policies":
        raise CliError(f"Unexpected argument {rest[0]}", EXIT_FAILURE)
    if command == "init":
        if sub:
            raise CliError(f"Unexpected argument {sub}", EXIT_FAILURE)
        return _command_init(emit)
    if command == "login":
        if sub:
            raise CliError(f"Unexpected argument {sub}", EXIT_FAILURE)
        return _command_login(flags, emit)
    if command == "check":
        if sub:
            raise CliError(f"Unexpected argument {sub}", EXIT_FAILURE)
        return _command_check(flags, emit, stderr)
    if command == "policies":
        if sub == "validate":
            if len(rest) > 1:
                raise CliError(f"Unexpected argument {rest[1]}", EXIT_FAILURE)
            return _command_validate(rest[0] if rest else None, emit)
        if sub == "pull":
            if rest:
                raise CliError(f"Unexpected argument {rest[0]}", EXIT_FAILURE)
            return _command_pull(flags, emit)
        if sub == "apply":
            if len(rest) > 1:
                raise CliError(f"Unexpected argument {rest[1]}", EXIT_FAILURE)
            return _command_apply(rest[0] if rest else None, flags, emit)
        raise CliError("Usage: vulnify policies validate|pull|apply", EXIT_FAILURE)
    if command == "test":
        if rest:
            raise CliError(f"Unexpected argument {rest[0]}", EXIT_FAILURE)
        return _command_test(sub, flags, emit)
    raise CliError(f"Unknown command {command}", EXIT_FAILURE)


def _package_version() -> str:
    from . import __version__

    return __version__


def _command_init(emit: Any) -> int:
    root = Path.cwd()
    policy_file = root / "vulnify" / "policies" / "example.yaml"
    test_file = root / "vulnify" / "tests" / "example.test.yaml"
    ignore_file = root / "vulnify" / ".gitignore"
    existing = [path for path in (policy_file, test_file, ignore_file) if path.exists()]
    if existing:
        names = ", ".join(_relative(root, path) for path in existing)
        raise CliError(f"Refusing to overwrite {names}", EXIT_FAILURE)
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text(EXAMPLE_POLICY_YAML, encoding="utf-8")
    test_file.write_text(EXAMPLE_TEST_YAML, encoding="utf-8")
    ignore_file.write_text(GITIGNORE_HINT, encoding="utf-8")
    created = ["vulnify/policies/example.yaml", "vulnify/tests/example.test.yaml", "vulnify/.gitignore"]
    text = "\n".join(f"created {name}" for name in created) + "\n" + GITIGNORE_STDOUT
    emit({"ok": True, "exitCode": 0, "created": created}, text)
    return EXIT_OK


def _command_login(flags: Dict[str, Any], emit: Any) -> int:
    stored = _read_credentials()
    api_key = flags.get("api-key") or os.environ.get("VULNIFY_API_KEY")
    if not api_key:
        raise CliError("Pass --api-key or set VULNIFY_API_KEY.", EXIT_AUTH)
    base_url = _strip_one_slash(flags.get("base-url") or os.environ.get("VULNIFY_BASE_URL") or stored.get("baseUrl") or DEFAULT_BASE_URL)
    _probe_api_key(base_url, str(api_key))
    path = _write_credentials(str(api_key), base_url)
    emit(
        {"ok": True, "exitCode": 0, "baseUrl": base_url, "credentials": path},
        f"Saved credentials to {path} (mode 0600).\nBase URL: {base_url}\n",
    )
    return EXIT_OK


def _command_check(flags: Dict[str, Any], emit: Any, stderr: Any) -> int:
    api_key, base_url = _require_key()
    agent = flags.get("agent")
    action = flags.get("action")
    resource = flags.get("resource")
    if not agent or not action or not resource:
        raise CliError("check requires --agent, --action, and --resource", EXIT_FAILURE)
    if action not in EVENT_ACTIONS:
        raise CliError(f"Unknown action {action}", EXIT_FAILURE)
    destination = flags.get("destination")
    if destination and destination not in DESTINATIONS:
        raise CliError(f"Unknown destination {destination}", EXIT_FAILURE)
    records = flags.get("records")
    records_affected = None
    if records is not None:
        if not re.fullmatch(r"\d+", str(records)):
            raise CliError("--records must be an integer >= 0", EXIT_FAILURE)
        records_affected = int(records)
    if flags.get("sensitive"):
        stderr("Warning: --sensitive is not sent. POST /v1/events has no sensitive flag.\n")
    if api_key.startswith("vln_live_"):
        stderr("Warning: this check uses a LIVE key and records a real event.\n")
    try:
        decision = Vulnify(api_key, base_url=base_url, timeout=10, retries=0).check(
            agent=str(agent),
            action=str(action),
            resource=str(resource),
            destination=str(destination) if destination else None,
            records_affected=records_affected,
        )
    except VulnifyError as err:
        text = str(err)
        if re.search(r"Vulnify request rejected \((401|403)\)", text):
            raise CliError(text, EXIT_AUTH) from None
        raise CliError(text, EXIT_FAILURE) from None
    if decision.degraded:
        message = "; ".join(decision.reasons).replace("fail_mode=", "failMode=") or "Vulnify could not be reached"
        raise CliError(message, EXIT_FAILURE, _decision_fields(decision))
    outcome = decision.final_decision if decision.final_decision is not None else decision.decision
    code = EXIT_OK if outcome == "ALLOW" else EXIT_REVIEW if outcome == "REVIEW" else EXIT_BLOCK
    score = ""
    if decision.risk_score is not None:
        score = f"score {decision.risk_score}" + (f" {decision.risk_level}" if decision.risk_level else "")
    policy = f"policy {decision.policy['name']}" if decision.policy and decision.policy.get("name") else "policy none"
    reasons = "; ".join(decision.reasons) if decision.reasons else ""
    lines = [line for line in (outcome, score, policy, reasons) if line]
    payload = {"ok": code == EXIT_OK, "exitCode": code, **_decision_fields(decision)}
    emit(payload, "\n".join(lines) + "\n")
    return code


def _command_pull(flags: Dict[str, Any], emit: Any) -> int:
    _require_yaml()
    api_key, base_url = _require_key()
    out_dir = Path(flags.get("out") or _default_dir("policies")).resolve()
    body = _api_request("GET", f"{base_url}/v1/policies", api_key)
    if not isinstance(body, dict) or not isinstance(body.get("policies"), list):
        raise CliError("Unexpected response from GET /v1/policies", EXIT_FAILURE, body)
    policies = sorted(body["policies"], key=lambda item: str(item.get("name", "") if isinstance(item, dict) else ""))
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Dict[str, str]] = []
    used = set()
    for policy in policies:
        if not isinstance(policy, dict) or not isinstance(policy.get("name"), str):
            raise CliError("A policy in the response has no name", EXIT_FAILURE, policy)
        base = _slug(policy["name"])
        file_name = f"{base}.yaml"
        number = 2
        while file_name in used:
            file_name = f"{base}-{number}.yaml"
            number += 1
        used.add(file_name)
        spec = {key: policy[key] for key in SPEC_KEYS if key in policy}
        metadata: Dict[str, Any] = {"name": policy["name"]}
        if isinstance(policy.get("id"), str):
            metadata["id"] = policy["id"]
        if isinstance(policy.get("updatedAt"), str):
            metadata["updatedAt"] = policy["updatedAt"]
        document = {"apiVersion": "vulnify.io/v1", "kind": "Policy", "metadata": metadata, "spec": spec}
        target = out_dir / file_name
        text = _dump_yaml(document)
        target.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        written.append({"name": policy["name"], "file": _relative(Path.cwd(), target)})
    human = ("\n".join(f"wrote {item['file']}" for item in written) + "\n") if written else "No policies.\n"
    emit({"ok": True, "exitCode": 0, "policies": written}, human)
    return EXIT_OK


def _command_apply(path: Optional[str], flags: Dict[str, Any], emit: Any) -> int:
    _require_yaml()
    target = str(Path(path).resolve()) if path else _default_dir("policies")
    docs = _read_kind(target, "Policy")
    api_key, base_url = _require_key()
    payload = {
        "policies": [_to_policy_spec(doc["data"]) for doc in docs],
        "prune": flags.get("prune") is True,
        "dryRun": flags.get("dry-run") is True,
    }
    body = _api_request("POST", f"{base_url}/v1/policies/apply", api_key, payload)
    if not isinstance(body, dict) or not isinstance(body.get("changes"), list):
        raise CliError("Unexpected response from POST /v1/policies/apply", EXIT_FAILURE, body)
    lines = ["dry-run" if body.get("dryRun") is True else "applied"]
    for change in body["changes"]:
        if not isinstance(change, dict):
            continue
        op = str(change.get("op") or "unknown")
        lines.append(f"{op:<9} {change.get('name') or ''}")
    result = dict(body)
    result["ok"] = True
    result["exitCode"] = 0
    emit(result, "\n".join(lines) + "\n")
    return EXIT_OK


def _command_validate(path: Optional[str], emit: Any) -> int:
    _require_yaml()
    target = str(Path(path).resolve()) if path else _default_dir("policies")
    docs = _read_kind(target, "Policy")
    count = len(docs)
    noun = "policy" if count == 1 else "policies"
    emit(
        {"ok": True, "exitCode": 0, "count": count, "schema": _schema_path()},
        f"Validated {count} {noun} against schema/policies.v1.json\n",
    )
    return EXIT_OK


def _command_test(path: Optional[str], flags: Dict[str, Any], emit: Any) -> int:
    _require_yaml()
    target = str(Path(path).resolve()) if path else _default_dir("tests")
    docs = _read_kind(target, "PolicyTest")
    cases: List[Dict[str, Any]] = []
    for doc in docs:
        raw_cases = doc["data"].get("cases")
        if not isinstance(raw_cases, list):
            continue
        for item in raw_cases:
            if isinstance(item, dict):
                cases.append(_to_test_case(item))
    if len(cases) > 200:
        raise CliError("POST /v1/policies/test accepts at most 200 cases", EXIT_FAILURE)
    payload: Dict[str, Any] = {"cases": cases}
    if flags.get("local"):
        policies = _read_kind(_default_dir("policies"), "Policy")
        payload["policies"] = [_to_policy_spec(doc["data"]) for doc in policies]
    api_key, base_url = _require_key()
    body = _api_request("POST", f"{base_url}/v1/policies/test", api_key, payload)
    if not isinstance(body, dict) or not isinstance(body.get("results"), list):
        raise CliError("Unexpected response from POST /v1/policies/test", EXIT_FAILURE, body)
    lines: List[str] = []
    failed = 0
    for result in body["results"]:
        if not isinstance(result, dict):
            failed += 1
            lines.append("FAIL  invalid result")
            continue
        name = str(result.get("name") or "")
        decision = str(result.get("decision") or "")
        matched = result.get("matchedPolicy")
        policy = "none" if matched is None else str(matched)
        passed = result.get("pass", _MISSING) if "pass" in result else _MISSING
        if passed is True:
            lines.append(f"PASS  {name}  {decision}  policy {policy}")
        elif passed is None:
            lines.append(f"SKIP  {name}  {decision}  policy {policy}")
        else:
            failed += 1
            lines.append(f"FAIL  {name}  {decision}  policy {policy}")
    code = EXIT_FAILURE if failed else EXIT_OK
    text = ("\n".join(lines) + "\n") if lines else ""
    emit({"failed": failed, "results": body["results"], "ok": code == EXIT_OK, "exitCode": code}, text or "\n")
    return code


class _Missing:
    pass


_MISSING = _Missing()


def _require_key() -> Tuple[str, str]:
    config = _resolve_config()
    if not config.get("apiKey"):
        raise CliError("No API key. Run vulnify login --api-key <key> or set VULNIFY_API_KEY.", EXIT_AUTH)
    return str(config["apiKey"]), str(config["baseUrl"])


def _credentials_file() -> Path:
    return Path.home() / ".config" / "vulnify" / "credentials.json"


def _read_credentials() -> Dict[str, Any]:
    path = _credentials_file()
    if not path.is_file():
        return {}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise CliError(f"Could not read {path}", EXIT_FAILURE) from None
    if not isinstance(parsed, dict):
        raise CliError(f"Could not read {path}", EXIT_FAILURE)
    out: Dict[str, Any] = {}
    if isinstance(parsed.get("apiKey"), str):
        out["apiKey"] = parsed["apiKey"]
    if isinstance(parsed.get("baseUrl"), str):
        out["baseUrl"] = parsed["baseUrl"]
    return out


def _resolve_config() -> Dict[str, Any]:
    stored = _read_credentials()
    env_key = os.environ.get("VULNIFY_API_KEY")
    env_url = os.environ.get("VULNIFY_BASE_URL")
    api_key = env_key or stored.get("apiKey")
    base_url = _strip_one_slash(env_url or stored.get("baseUrl") or DEFAULT_BASE_URL)
    return {"apiKey": api_key, "baseUrl": base_url}


def _write_credentials(api_key: str, base_url: str) -> str:
    path = _credentials_file()
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    text = json.dumps({"apiKey": api_key, "baseUrl": base_url}, indent=2) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return str(path)


def _strip_one_slash(url: str) -> str:
    if url.endswith("/"):
        return url[:-1]
    return url


def _probe_api_key(base_url: str, api_key: str) -> None:
    url = f"{base_url}/v1/events/{LOGIN_PROBE_ID}"
    status, body, network = _raw_request("GET", url, api_key, None, 15)
    if network is not None:
        raise CliError(f"Vulnify could not be reached ({network})", EXIT_FAILURE)
    message = _message_of(body)
    if status == 401:
        raise CliError(message or "Invalid API key", EXIT_AUTH, body)
    if re.match(r"^Cannot (GET|POST|PUT|PATCH|DELETE)\b", message):
        raise CliError(f"This base URL has no decision API ({base_url})", EXIT_FAILURE, body)
    if status in (200, 403, 404):
        return
    raise CliError(message or f"Vulnify responded {status}", EXIT_FAILURE, body)


def _api_request(method: str, url: str, api_key: str, body: Optional[Dict[str, Any]] = None) -> Any:
    status, parsed, network = _raw_request(method, url, api_key, body, 20)
    if network is not None:
        raise CliError(f"Vulnify could not be reached ({network})", EXIT_FAILURE)
    if status == 404:
        raise CliError(UNSUPPORTED_MESSAGE, EXIT_UNSUPPORTED)
    if status in (401, 403):
        raise CliError(_message_of(parsed) or f"Vulnify rejected the API key ({status})", EXIT_AUTH, parsed)
    if status >= 400:
        raise CliError(_format_api_error(status, parsed), EXIT_FAILURE, parsed)
    return parsed


def _raw_request(
    method: str,
    url: str,
    api_key: str,
    body: Optional[Dict[str, Any]],
    timeout: float,
) -> Tuple[int, Any, Optional[str]]:
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return response.status, _parse_body(raw), None
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8")
        return err.code, _parse_body(raw), None
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        reason = getattr(err, "reason", None)
        message = str(reason or err)
        return 0, {}, message


def _parse_body(raw: str) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        return {"message": raw}


def _message_of(body: Any) -> str:
    if not isinstance(body, dict):
        return ""
    message = body.get("message")
    if isinstance(message, str) and message:
        return message
    error = body.get("error")
    if isinstance(error, str) and error:
        return error
    return ""


def _format_api_error(status: int, body: Any) -> str:
    if isinstance(body, dict) and isinstance(body.get("fields"), dict):
        lines = []
        for key, value in body["fields"].items():
            rendered = value if isinstance(value, str) else json.dumps(value)
            lines.append(f"{key}: {rendered}")
        if lines:
            return "\n".join(lines)
    return _message_of(body) or f"Vulnify responded {status}"


def _decision_fields(decision: Any) -> Dict[str, Any]:
    return {
        "id": decision.id,
        "decision": decision.decision,
        "finalDecision": decision.final_decision,
        "evaluatedDecision": decision.evaluated_decision,
        "monitored": decision.monitored,
        "review": decision.review,
        "riskLevel": decision.risk_level,
        "riskScore": decision.risk_score,
        "reasons": decision.reasons,
        "policy": decision.policy,
        "dlpFindings": decision.dlp_findings,
        "lgpdCategories": decision.lgpd_categories,
        "quotaExceeded": decision.quota_exceeded,
        "sandbox": decision.sandbox,
        "degraded": decision.degraded,
    }


def _default_dir(folder: str) -> str:
    return str(Path.cwd() / "vulnify" / folder)


def _relative(cwd: Path, path: Path) -> str:
    rel = os.path.relpath(str(path), str(cwd))
    if rel == ".":
        return str(path)
    return Path(rel).as_posix()


def _display_path(path: str) -> str:
    rel = _relative(Path.cwd(), Path(path))
    return rel or path


def _read_kind(path: str, kind: str) -> List[Dict[str, Any]]:
    found = _list_yaml_files(path)
    label = _display_path(path)
    if not found:
        raise CliError(f"No YAML files in {label}", EXIT_FAILURE)
    docs: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    schema_ref = "#/$defs/policyDocument" if kind == "Policy" else "#/$defs/policyTestDocument"
    for file_path in found:
        loaded = _load_documents(file_path)
        errors.extend(loaded["errors"])
        for doc in loaded["docs"]:
            if doc["kind"] != kind:
                continue
            errors.extend(_validate_document(doc, schema_ref))
            docs.append(doc)
    if errors:
        lines = [_format_schema_error(err) for err in errors]
        raise CliError("\n".join(lines), EXIT_FAILURE, errors)
    if not docs:
        raise CliError(f"No kind: {kind} documents in {label}", EXIT_FAILURE)
    if kind == "Policy":
        names: Dict[str, str] = {}
        for doc in docs:
            name = _policy_name(doc["data"])
            if not name:
                continue
            prev = names.get(name)
            if prev:
                raise CliError(
                    f'Duplicate policy name "{name}" in {_display_path(prev)} and {_display_path(doc["file"])}',
                    EXIT_FAILURE,
                )
            names[name] = doc["file"]
    return docs


def _list_yaml_files(root: str) -> List[str]:
    path = Path(root)
    if not path.exists():
        return []
    if path.is_file():
        return [str(path)]
    found: List[str] = []

    def walk(directory: Path) -> None:
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            if entry.name == "node_modules" or entry.name.startswith("."):
                continue
            if entry.is_dir():
                walk(entry)
            elif re.search(r"\.ya?ml$", entry.name, re.IGNORECASE):
                found.append(str(entry))

    walk(path)
    return found


def _load_documents(file_path: str) -> Dict[str, Any]:
    import yaml

    text = Path(file_path).read_text(encoding="utf-8")
    docs: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    try:
        nodes = list(yaml.compose_all(text))
        loaded = list(yaml.safe_load_all(text))
    except yaml.YAMLError as err:
        mark = getattr(err, "problem_mark", None)
        line = (mark.line + 1) if mark is not None else 1
        problem = getattr(err, "problem", None) or str(err)
        return {"docs": [], "errors": [{"file": file_path, "line": line, "message": problem}]}
    if len(nodes) != len(loaded):
        return {"docs": [], "errors": [{"file": file_path, "line": 1, "message": "Could not read YAML documents"}]}
    for index, (node, data) in enumerate(zip(nodes, loaded)):
        line = (node.start_mark.line + 1) if node is not None else 1
        if data is None:
            continue
        if not isinstance(data, dict):
            errors.append({"file": file_path, "line": line, "message": f"document {index + 1} must be a mapping"})
            continue
        kind = data.get("kind") if isinstance(data.get("kind"), str) else ""
        docs.append({"file": file_path, "line": line, "kind": kind, "data": data, "node": node, "text": text})
    return {"docs": docs, "errors": errors}


def _validate_document(doc: Dict[str, Any], schema_ref: str) -> List[Dict[str, Any]]:
    validator = _validator(schema_ref)
    errors = []
    for error in validator.iter_errors(doc["data"]):
        formatted = _format_jsonschema(error)
        line = _node_line(doc.get("node"), formatted["path"])
        errors.append({"file": doc["file"], "line": line, "message": formatted["message"]})
    return errors


def _format_jsonschema(error: Any) -> Dict[str, Any]:
    path = [str(part) for part in error.absolute_path]
    validator = error.validator
    if validator == "additionalProperties" and isinstance(error.instance, dict):
        allowed = set()
        if isinstance(error.schema, dict):
            allowed = set(error.schema.get("properties", {}))
        extras = [key for key in error.instance.keys() if key not in allowed]
        extra = extras[0] if extras else None
        if extra:
            path.append(str(extra))
        pointer = "/" + "/".join(path) if path else "/"
        return {"path": path, "message": f"{pointer} must NOT have additional properties"}
    pointer = "/" + "/".join(path) if path else "/"
    if validator == "enum":
        message = f"{pointer} must be equal to one of the allowed values"
    elif validator == "const":
        message = f"{pointer} must be equal to constant"
    elif validator == "required":
        missing = error.message
        match = re.search(r"'([^']+)'", str(missing))
        name = match.group(1) if match else "property"
        message = f"{pointer} must have required property '{name}'"
    elif validator == "type":
        expected = error.validator_value
        if isinstance(expected, list):
            expected = " or ".join(str(item) for item in expected)
        message = f"{pointer} must be {expected}"
    elif validator == "pattern":
        message = f'{pointer} must match pattern "{error.validator_value}"'
    elif validator == "minimum":
        message = f"{pointer} must be >= {error.validator_value}"
    elif validator == "maximum":
        message = f"{pointer} must be <= {error.validator_value}"
    elif validator == "minLength":
        message = f"{pointer} must NOT have fewer than {error.validator_value} characters"
    elif validator == "maxLength":
        message = f"{pointer} must NOT have more than {error.validator_value} characters"
    elif validator == "minItems":
        message = f"{pointer} must NOT have fewer than {error.validator_value} items"
    elif validator == "uniqueItems":
        message = f"{pointer} must NOT have duplicate items"
    else:
        message = f"{pointer} {error.message}"
    return {"path": path, "message": message}


def _format_schema_error(err: Dict[str, Any]) -> str:
    return f"{_display_path(err['file'])}:{err['line']}: {err['message']}"


def _node_line(node: Any, path: Sequence[Any]) -> int:
    import yaml

    current = node
    if current is None:
        return 1
    for index, part in enumerate(path):
        if isinstance(current, yaml.MappingNode):
            match = None
            for key_node, value_node in current.value:
                if isinstance(key_node, yaml.ScalarNode) and key_node.value == str(part):
                    match = (key_node, value_node)
                    break
            if match is None:
                break
            key_node, value_node = match
            if index == len(path) - 1:
                return key_node.start_mark.line + 1
            current = value_node
            continue
        if isinstance(current, yaml.SequenceNode):
            try:
                current = current.value[int(part)]
            except (ValueError, IndexError, TypeError):
                break
            continue
        break
    return current.start_mark.line + 1


def _policy_name(data: Dict[str, Any]) -> str:
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        return ""
    name = metadata.get("name")
    return name if isinstance(name, str) else ""


def _to_policy_spec(data: Dict[str, Any]) -> Dict[str, Any]:
    spec = data.get("spec") if isinstance(data.get("spec"), dict) else {}
    out: Dict[str, Any] = {"name": _policy_name(data)}
    for key in SPEC_KEYS:
        if key in spec:
            out[key] = spec[key]
    return out


def _to_test_case(data: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"name": data.get("name"), "input": data.get("input")}
    if "expect" in data:
        out["expect"] = data["expect"]
    return out


def _slug(name: str) -> str:
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", name.strip().lower())
    cleaned = re.sub(r"^-+|-+$", "", cleaned)
    return cleaned or "policy"


def _schema_path() -> str:
    return str(files("vulnify.schema").joinpath("policies.v1.json"))


def _load_schema() -> Dict[str, Any]:
    raw = files("vulnify.schema").joinpath("policies.v1.json").read_text(encoding="utf-8")
    schema = json.loads(raw)
    if not isinstance(schema, dict):
        raise CliError("Policy schema is not a JSON object", EXIT_FAILURE)
    return schema


def _validator(schema_ref: str) -> Any:
    import jsonschema
    from referencing import Registry, Resource

    schema = _load_schema()
    registry = Registry().with_resource(schema["$id"], Resource.from_contents(schema))
    return jsonschema.Draft202012Validator({"$ref": schema["$id"] + schema_ref}, registry=registry)


def _dump_yaml(data: Dict[str, Any]) -> str:
    import yaml

    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096)


def _require_yaml() -> None:
    try:
        import yaml  # noqa: F401
    except ImportError:
        raise CliError(
            'The vulnify CLI needs the cli extra. Install it with: pip install "vulnify[cli]"',
            EXIT_FAILURE,
        ) from None


if __name__ == "__main__":
    console_main()
