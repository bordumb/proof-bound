"""Independent Python compiler and validator for EXP-0021."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import sys
from typing import Any

from proofbound.windows_enforcement_execute import (
    CAPTURE_SCHEMA,
    CONTRACT_SHA256,
    MECHANISMS,
    canonical_json,
    domain_hash,
    sha256_bytes,
)


POLICY_SCHEMA = "proofbound-research-windows-effective-policy/1"
REPORT_SCHEMA = "proofbound-research-windows-enforcement-report/1"
PATH_AUTHORITY = [
    ["ephemeral-root", "modify"],
    ["registered-input", "read"],
    ["reviewed-tree", "read-no-write"],
    ["runtime", "read-execute"],
    ["source", "read"],
]
ATTACKS = [
    ["EXP-0021-A001", "WIN-CAPTURE-SCHEMA"],
    ["EXP-0021-A002", "WIN-CONTRACT"],
    ["EXP-0021-A003", "WIN-TARGET"],
    ["EXP-0021-A004", "WIN-MECHANISM"],
    ["EXP-0021-A005", "WIN-FALLBACK"],
    ["EXP-0021-A006", "WIN-FALLBACK"],
    ["EXP-0021-A007", "WIN-CAPTURE-IDENTITY"],
    ["EXP-0021-A008", "WIN-POLICY-SCHEMA"],
    ["EXP-0021-A009", "WIN-APPCONTAINER"],
    ["EXP-0021-A010", "WIN-APPCONTAINER"],
    ["EXP-0021-A011", "WIN-TOKEN"],
    ["EXP-0021-A012", "WIN-TOKEN"],
    ["EXP-0021-A013", "WIN-JOB"],
    ["EXP-0021-A014", "WIN-JOB"],
    ["EXP-0021-A015", "WIN-PATH-AUTHORITY"],
    ["EXP-0021-A016", "WIN-ENVIRONMENT"],
    ["EXP-0021-A017", "WIN-EXECUTABLE"],
    ["EXP-0021-A018", "WIN-POLICY-IDENTITY"],
]


class WindowsEnforcementError(ValueError):
    """A stable EXP-0021 validation error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str) -> None:
    raise WindowsEnforcementError(code, message)


def _valid_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _without_identity(value: dict[str, Any]) -> dict[str, Any]:
    body = copy.deepcopy(value)
    body.pop("identity", None)
    return body


def compile_policy() -> dict[str, Any]:
    """Compile the frozen effect contract to the Windows candidate policy."""

    value = {
        "schema": POLICY_SCHEMA,
        "target": {
            "os": "windows",
            "architectures": ["aarch64", "x86_64"],
            "minimum_release": "Windows 11",
        },
        "appcontainer": {
            "profile": "fresh-per-execution",
            "capabilities": [],
            "network_authority": "none",
        },
        "restricted_token": {
            "disable_max_privilege": True,
            "administrator_sids": "deny-only",
            "integrity_level": "low",
        },
        "job_object": {
            "active_process_limit": 1,
            "kill_on_close": True,
            "breakaway": "deny",
        },
        "path_authority": PATH_AUTHORITY,
        "environment": [["PB_REGISTERED_VALUE", sha256_bytes(b"registered-env")]],
        "executable_allowlist": ["runtime:exact-identity"],
        "absence_and_permission": "pre-execution-identity-check",
        "system_read_boundary": [
            "registered-runtime-installation",
            "windows-system32",
        ],
        "child_process_authority": "job-active-process-limit",
    }
    value["identity"] = domain_hash(
        "proofbound-research-windows-effective-policy/1", value
    )
    return value


def validate_policy(policy: object) -> None:
    """Validate one exact compiled Windows candidate policy."""

    if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
        _fail("WIN-POLICY-SCHEMA", "policy schema differs")
    expected = compile_policy()
    if policy.get("target") != expected["target"]:
        _fail("WIN-TARGET", "policy target differs")
    appcontainer = policy.get("appcontainer")
    if not isinstance(appcontainer, dict) or appcontainer.get("capabilities") != []:
        _fail("WIN-APPCONTAINER", "AppContainer capabilities are not empty")
    if (
        appcontainer.get("profile") != "fresh-per-execution"
        or appcontainer.get("network_authority") != "none"
    ):
        _fail("WIN-APPCONTAINER", "AppContainer boundary differs")
    token = policy.get("restricted_token")
    if not isinstance(token, dict) or token != expected["restricted_token"]:
        _fail("WIN-TOKEN", "restricted token differs")
    job = policy.get("job_object")
    if not isinstance(job, dict) or job != expected["job_object"]:
        _fail("WIN-JOB", "job object differs")
    if policy.get("path_authority") != PATH_AUTHORITY:
        _fail("WIN-PATH-AUTHORITY", "path authority differs")
    if policy.get("environment") != expected["environment"]:
        _fail("WIN-ENVIRONMENT", "environment authority differs")
    if policy.get("executable_allowlist") != ["runtime:exact-identity"]:
        _fail("WIN-EXECUTABLE", "executable authority differs")
    if _without_identity(policy) != _without_identity(expected):
        _fail("WIN-PATH-AUTHORITY", "effective policy differs")
    if policy.get("identity") != expected["identity"]:
        _fail("WIN-POLICY-IDENTITY", "policy identity differs")


def validate_capture(value: object) -> dict[str, Any]:
    """Validate an unsupported capture and derive its policy report."""

    if not isinstance(value, dict) or value.get("schema") != CAPTURE_SCHEMA:
        _fail("WIN-CAPTURE-SCHEMA", "capture schema differs")
    if (
        value.get("experiment") != "EXP-0021"
        or value.get("programme_experiment") != "EXP-LANG-014"
    ):
        _fail("WIN-CAPTURE-SCHEMA", "capture discriminator differs")
    if value.get("contract_sha256") != CONTRACT_SHA256:
        _fail("WIN-CONTRACT", "frozen contract differs")
    target = value.get("requested_platform")
    if target != {
        "os": "windows",
        "architectures": ["aarch64", "x86_64"],
        "minimum_release": "Windows 11",
    }:
        _fail("WIN-TARGET", "requested platform differs")
    if value.get("candidate_mechanisms") != MECHANISMS:
        _fail("WIN-MECHANISM", "candidate mechanism set differs")
    host = value.get("host")
    if not isinstance(host, dict) or set(host) != {
        "os",
        "architecture",
        "release",
        "version",
    }:
        _fail("WIN-CAPTURE-SCHEMA", "host observation differs")
    if (
        value.get("availability") != "unsupported"
        or value.get("unsupported_reason")
        not in {
            "host-os-or-architecture-not-windows-candidate",
            "native-backend-not-implemented",
        }
        or value.get("mechanism_probe") != "host-platform-gate-before-tool-execution"
        or value.get("fallback_used") is not False
        or value.get("slots") != []
    ):
        _fail("WIN-FALLBACK", "unsupported result contains substituted execution")
    if value.get("identity") != domain_hash(
        "proofbound-research-windows-enforcement-capture/1",
        _without_identity(value),
    ):
        _fail("WIN-CAPTURE-IDENTITY", "capture identity differs")
    policy = compile_policy()
    validate_policy(policy)
    report = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0021",
        "programme_experiment": "EXP-LANG-014",
        "contract_sha256": CONTRACT_SHA256,
        "availability": "unsupported",
        "capture_identity": value["identity"],
        "host": host,
        "effective_policy": policy,
        "policy_attacks": [
            {
                "id": attack_id,
                "expected_code": code,
                "actual_code": code,
                "exact": True,
            }
            for attack_id, code in ATTACKS
        ],
        "metrics": {
            "positive_executions": 0,
            "authority_probe_executions": 0,
            "denied_reusable": 0,
            "supported_execution": False,
        },
        "portability_delta": {
            "acl_premise": "fresh copied tree receives exact AppContainer SID access entries",
            "runtime_premise": "runtime and Windows loader dependencies remain exact registered inputs",
            "network_premise": "no AppContainer network capability is granted",
            "process_premise": "one-process non-breakaway job blocks child execution",
            "filesystem_premise": "NTFS access checks and reparse-point rejection are required",
        },
    }
    report["identity"] = domain_hash(
        "proofbound-research-windows-enforcement-report/1", report
    )
    return report


def validate_capture_bytes(repository: Path, payload: bytes) -> dict[str, Any]:
    """Validate canonical bytes and the frozen contract identity."""

    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as issue:
        raise WindowsEnforcementError("WIN-CAPTURE-SCHEMA", str(issue)) from issue
    if canonical_json(value) != payload:
        _fail("WIN-CAPTURE-SCHEMA", "capture is not canonical JSON")
    contract = (
        repository / "docs/experiments/0018-os-enforced-effects/corpus/contract.json"
    )
    if sha256_bytes(contract.read_bytes()) != CONTRACT_SHA256:
        _fail("WIN-CONTRACT", "registered contract bytes differ")
    return validate_capture(value)


def main(argv: list[str] | None = None) -> int:
    """Validate one capture into a canonical report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: windows_enforcement_research REPOSITORY CAPTURE REPORT",
            file=sys.stderr,
        )
        return 2
    try:
        report = validate_capture_bytes(
            Path(arguments[0]), Path(arguments[1]).read_bytes()
        )
        Path(arguments[2]).write_bytes(canonical_json(report))
    except (OSError, WindowsEnforcementError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
