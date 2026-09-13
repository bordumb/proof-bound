"""Independent effect-plan model for Proofbound language research."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

PLAN_SCHEMA = "proofbound-research-effect-plan/1"
TRACE_SCHEMA = "proofbound-research-effect-trace/1"
ENFORCEMENT_SCHEMA = "proofbound-research-effect-enforcement/1"
INVALIDATION_SCHEMA = "proofbound-research-effect-invalidation/1"
REPORT_SCHEMA = "proofbound-research-effect-model-report/1"


class EffectFailure(ValueError):
    """Report one exact effect-model rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical_json(value: object) -> bytes:
    """Encode a research record as compact sorted-key JSON."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def domain_hash(domain: str, payload: bytes) -> str:
    """Return the experiment's domain-separated SHA-256 identity."""

    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()


def sha256_bytes(payload: bytes) -> str:
    """Return a raw-byte SHA-256 identity."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load_effect_corpus(
    root: Path, corpus_dir: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Load and validate the frozen plans, receipt, and attacks."""

    plans = _load_json(root / corpus_dir / "plans.json")
    enforcement = _load_json(root / corpus_dir / "enforcement.json")
    attacks = _load_json(root / corpus_dir / "attacks.json")
    _exact_keys(plans, {"schema", "plans"}, "EFFECT-DECODE")
    _exact_keys(attacks, {"schema", "attacks"}, "EFFECT-DECODE")
    if plans["schema"] != "proofbound-research-effect-corpus/1":
        _raise("EFFECT-SCHEMA", "unexpected corpus schema")
    if attacks["schema"] != "proofbound-research-effect-attacks/1":
        _raise("EFFECT-SCHEMA", "unexpected attack schema")
    validate_enforcement(enforcement)
    plan_ids: set[str] = set()
    for plan in plans["plans"]:
        if plan.get("id") in plan_ids:
            _raise("EFFECT-SET-DUPLICATE", "duplicate plan ID")
        plan_ids.add(plan.get("id"))
        validate_effect_plan(plan, enforcement)
    return plans, enforcement, attacks


def validate_effect_plan(
    plan: dict[str, Any], enforcement: dict[str, Any] | None
) -> None:
    """Validate one closed typed effect plan."""

    _exact_keys(plan, {"schema", "id", "effects", "workload"}, "EFFECT-DECODE")
    if plan["schema"] != PLAN_SCHEMA:
        _raise("EFFECT-SCHEMA", "unexpected effect-plan schema")
    _validate_id(plan["id"], "plan")
    effects = plan["effects"]
    if not isinstance(effects, list) or not effects:
        _raise("EFFECT-SET-EMPTY", "effect set is empty")
    ids = [effect.get("id") for effect in effects]
    if not all(isinstance(item, str) for item in ids) or ids != sorted(set(ids)):
        _raise("EFFECT-SET-DUPLICATE", "effects must form a strict lexical set")
    for effect in effects:
        _validate_effect(effect, enforcement)
    _validate_workload(plan)


def execute_effect_plan(
    root: Path, plan: dict[str, Any], enforcement: dict[str, Any] | None
) -> dict[str, Any]:
    """Execute one plan through the mediated research host."""

    validate_effect_plan(plan, enforcement)
    runner = _Runner(root, plan, enforcement)
    workload = plan["workload"]
    kind = workload["kind"]
    if kind == "hidden-read":
        runner.read_file(workload["policy_effect"])
    elif kind == "mutation-replay":
        target = runner.read_file(workload["target_effect"])
        mutant = runner.read_file(workload["mutant_effect"])
        witness = runner.read_file(workload["witness_effect"])
        if (
            target != b"mode=strict\nlimit=10\n"
            or mutant != b"mode=strict\nlimit=none\n"
            or witness != b"reject-unbounded\n"
        ):
            _raise("EFFECT-MUTATION-POSTIMAGE", "mutation fixture semantics changed")
        runner.write_ephemeral(
            workload["output_effect"], "ephemeral/mutation/target.txt", mutant
        )
    elif kind == "distribution-build":
        files: list[dict[str, Any]] = []
        for effect_id in workload["payload_effects"]:
            content = runner.read_file(effect_id)
            effect = runner.effect(effect_id)
            try:
                text = content.decode()
            except UnicodeDecodeError:
                _raise("EFFECT-DISTRIBUTION-INVENTORY", "payload is not UTF-8")
            files.append(
                {
                    "content": text,
                    "path": effect["path"],
                    "sha256": effect["sha256"],
                    "size_bytes": effect["size_bytes"],
                }
            )
        runner.require_absent(workload["absent_effect"])
        output = canonical_json(
            {
                "files": files,
                "schema": "proofbound-research-distribution-output/1",
            }
        )
        runner.write_ephemeral(
            workload["output_effect"],
            "ephemeral/distribution/package.json",
            output,
        )
    elif kind == "subprocess-boundary":
        runner.execute(workload["execute_effect"])
    elif kind == "secret-read":
        runner.read_secret(workload["environment_effect"])
    else:
        _raise("EFFECT-PLAN-INVALID", "unknown workload")
    return runner.finish()


def validate_effect_trace(
    root: Path,
    plan: dict[str, Any],
    enforcement: dict[str, Any] | None,
    trace: dict[str, Any],
) -> None:
    """Independently recompute and validate a complete effect trace."""

    _exact_keys(
        trace,
        {
            "schema",
            "plan_id",
            "plan_identity",
            "observations",
            "dispositions",
            "outputs",
            "cache_eligible",
            "identity",
        },
        "EFFECT-DECODE",
    )
    validate_effect_plan(plan, enforcement)
    if (
        trace["schema"] != TRACE_SCHEMA
        or trace["plan_id"] != plan["id"]
        or trace["plan_identity"] != _plan_identity(plan)
        or trace["identity"] != _trace_identity(trace)
    ):
        _raise("EFFECT-TRACE-UNBOUND", "trace is not bound to its plan")
    effects = {effect["id"]: effect for effect in plan["effects"]}
    observed: set[str] = set()
    for index, observation in enumerate(trace["observations"]):
        _exact_keys(
            observation,
            {"index", "effect_id", "kind", "disposition", "value"},
            "EFFECT-TRACE-UNBOUND",
        )
        effect = effects.get(observation["effect_id"])
        if (
            observation["index"] != index
            or observation["disposition"] != "observed"
            or effect is None
            or observation["effect_id"] in observed
            or observation["kind"] != effect["kind"]
        ):
            _raise("EFFECT-TRACE-UNBOUND", "observation declaration is invalid")
        observed.add(observation["effect_id"])
    expected_dispositions = [
        {
            "effect_id": effect["id"],
            "disposition": "observed" if effect["id"] in observed else "unused",
        }
        for effect in plan["effects"]
    ]
    if trace["dispositions"] != expected_dispositions:
        _raise("EFFECT-TRACE-DISPOSITION", "declaration disposition is invalid")
    expected = execute_effect_plan(root, plan, enforcement)
    if trace["outputs"] != expected["outputs"]:
        if plan["workload"]["kind"] == "mutation-replay":
            _raise("EFFECT-MUTATION-POSTIMAGE", "mutation postimage changed")
        if plan["workload"]["kind"] == "distribution-build":
            _raise("EFFECT-DISTRIBUTION-INVENTORY", "distribution inventory changed")
        _raise("EFFECT-TRACE-UNBOUND", "unexpected output")
    eligible = _cache_eligible(plan, trace["observations"], enforcement)
    if trace["cache_eligible"] != eligible:
        if any(
            effect["kind"] == "read-environment"
            and effect["secret"]
            and effect["id"] in observed
            for effect in plan["effects"]
        ):
            _raise("EFFECT-SECRET-NONREUSABLE", "secret trace cannot be reused")
        if any(
            effect["kind"] == "execute"
            and effect["boundary"] == "opaque"
            and effect["id"] in observed
            for effect in plan["effects"]
        ):
            _raise("EFFECT-SUBPROCESS-OPAQUE", "opaque execution cannot be reused")
        _raise("EFFECT-TRACE-UNBOUND", "cache eligibility was authored")
    if trace["observations"] != expected["observations"]:
        _raise("EFFECT-TRACE-UNBOUND", "observation values changed")


def derive_effect_invalidation(
    plan: dict[str, Any],
    old_trace: dict[str, Any],
    changed_files: dict[str, bytes],
) -> dict[str, Any]:
    """Derive invalidation from changed consumed artifacts only."""

    observations = deepcopy(old_trace["observations"])
    changed_effects: list[str] = []
    for effect in plan["effects"]:
        if effect["kind"] != "read-file" or effect["path"] not in changed_files:
            continue
        changed_effects.append(effect["id"])
        value = next(
            item["value"] for item in observations if item["effect_id"] == effect["id"]
        )
        value["sha256"] = sha256_bytes(changed_files[effect["path"]])
        value["size_bytes"] = len(changed_files[effect["path"]])
    hypothetical = deepcopy(old_trace)
    hypothetical["observations"] = observations
    hypothetical["identity"] = _trace_identity(hypothetical)
    return {
        "schema": INVALIDATION_SCHEMA,
        "plan_id": plan["id"],
        "old_trace_identity": old_trace["identity"],
        "new_trace_identity": hypothetical["identity"],
        "invalidated": bool(changed_effects),
        "changed_effects": sorted(changed_effects),
    }


def execute_effect_corpus(
    root: Path, corpus_dir: Path, repetitions: int
) -> dict[str, Any]:
    """Execute all frozen plans, attacks, and invalidation controls."""

    if not 1 <= repetitions <= 100:
        _raise("EFFECT-PLAN-INVALID", "invalid repetition count")
    plans_doc, enforcement, attacks_doc = load_effect_corpus(root, corpus_dir)
    expected = _load_json(root / corpus_dir / "expected.json")
    _validate_expected(root, plans_doc, enforcement, expected, repetitions)
    plan_results: list[dict[str, Any]] = []
    traces: dict[str, dict[str, Any]] = {}
    route_outputs: list[dict[str, Any]] = []
    for plan in plans_doc["plans"]:
        trace = execute_effect_plan(root, plan, enforcement)
        validate_effect_trace(root, plan, enforcement, trace)
        identities: list[str] = []
        for _ in range(repetitions):
            repeated = execute_effect_plan(root, plan, enforcement)
            if repeated != trace:
                _raise("EFFECT-NONDETERMINISTIC", "trace changed")
            identities.append(repeated["identity"])
        plan_results.append(
            {
                "id": plan["id"],
                "plan_bytes": len(canonical_json(plan)),
                "trace_bytes": len(canonical_json(trace)),
                "declaration_count": len(plan["effects"]),
                "observation_count": len(trace["observations"]),
                "repetition_trace_identities": identities,
                "trace": trace,
            }
        )
        traces[plan["id"]] = trace
        route_outputs.extend(trace["outputs"])
    plan_results.sort(key=lambda item: item["id"])
    route_outputs.sort(
        key=lambda item: (item["path"], item["sha256"], item["size_bytes"])
    )
    expected_outputs = sorted(
        [expected["distribution_output"], expected["mutation_output"]],
        key=lambda item: (item["path"], item["sha256"], item["size_bytes"]),
    )
    if route_outputs != expected_outputs:
        _raise("EFFECT-OUTPUT-IDENTITY", "route outputs differ from corpus")
    plans = {plan["id"]: plan for plan in plans_doc["plans"]}
    attacks = [
        _evaluate_attack(root, plans[attack["base"]], enforcement, attack)
        for attack in attacks_doc["attacks"]
    ]
    hidden = plans["hidden-reader"]
    hidden_trace = traces["hidden-reader"]
    policy = {
        "docs/experiments/0012-effect-checked-replay/corpus/fixtures/hidden/policy.txt": b"deny\n"
    }
    unrelated = {
        "docs/experiments/0012-effect-checked-replay/corpus/fixtures/hidden/unrelated.txt": b"changed-only\n"
    }
    return {
        "schema": REPORT_SCHEMA,
        "plans": plan_results,
        "attacks": attacks,
        "invalidation": [
            {
                "id": "policy-change",
                "decisions": [
                    derive_effect_invalidation(hidden, hidden_trace, policy)
                    for _ in range(repetitions)
                ],
            },
            {
                "id": "unrelated-change",
                "decisions": [
                    derive_effect_invalidation(hidden, hidden_trace, unrelated)
                    for _ in range(repetitions)
                ],
            },
        ],
        "route_outputs": route_outputs,
    }


class _Runner:
    def __init__(
        self,
        root: Path,
        plan: dict[str, Any],
        enforcement: dict[str, Any] | None,
    ) -> None:
        self.root = root
        self.plan = plan
        self.enforcement = enforcement
        self.observations: list[dict[str, Any]] = []
        self.outputs: list[dict[str, Any]] = []
        self.consumed: set[str] = set()

    def effect(self, effect_id: str) -> dict[str, Any]:
        for effect in self.plan["effects"]:
            if effect["id"] == effect_id:
                return effect
        _raise("EFFECT-TRACE-UNBOUND", f"unknown effect {effect_id}")

    def observe(self, effect: dict[str, Any], value: dict[str, Any]) -> None:
        if effect["id"] in self.consumed:
            _raise("EFFECT-TRACE-UNBOUND", "effect consumed twice")
        self.consumed.add(effect["id"])
        self.observations.append(
            {
                "index": len(self.observations),
                "effect_id": effect["id"],
                "kind": effect["kind"],
                "disposition": "observed",
                "value": value,
            }
        )

    def read_file(self, effect_id: str) -> bytes:
        effect = self.effect(effect_id)
        if effect["kind"] != "read-file":
            _raise("EFFECT-READ-UNDECLARED", "effect is not a file read")
        payload, mode = _read_regular(self.root, effect["path"])
        if (
            sha256_bytes(payload) != effect["sha256"]
            or len(payload) != effect["size_bytes"]
            or mode != effect["mode"]
        ):
            _raise("EFFECT-INPUT-DRIFT", f"{effect['path']} changed")
        self.observe(
            effect,
            {
                "type": "artifact",
                "path": effect["path"],
                "sha256": effect["sha256"],
                "size_bytes": effect["size_bytes"],
                "mode": effect["mode"],
            },
        )
        return payload

    def require_absent(self, effect_id: str) -> None:
        effect = self.effect(effect_id)
        if effect["kind"] != "require-absent":
            _raise("EFFECT-PLAN-INVALID", "effect is not absence")
        self.observe(effect, {"type": "absence", "path": effect["path"]})

    def write_ephemeral(self, effect_id: str, path: str, payload: bytes) -> None:
        effect = self.effect(effect_id)
        if effect["kind"] != "write-ephemeral" or not _strict_descendant(
            effect["root"], path
        ):
            _raise("EFFECT-WRITE-ESCAPE", "output escaped boundary")
        output = {
            "path": path,
            "sha256": sha256_bytes(payload),
            "size_bytes": len(payload),
        }
        self.observe(effect, {"type": "output", **output})
        self.outputs.append(output)

    def execute(self, effect_id: str) -> None:
        effect = self.effect(effect_id)
        if effect["kind"] != "execute":
            _raise("EFFECT-EXEC-UNDECLARED", "effect is not execution")
        if effect["boundary"] == "externally-enforced":
            validate_effect_plan(self.plan, self.enforcement)
        payload, mode = _read_regular(self.root, effect["tool"]["path"])
        if (
            sha256_bytes(payload) != effect["tool"]["sha256"]
            or len(payload) != effect["tool"]["size_bytes"]
            or mode != effect["tool"]["mode"]
        ):
            _raise("EFFECT-EXEC-IDENTITY", "registered executable changed")
        value = {
            "type": "execution",
            "tool": deepcopy(effect["tool"]),
            "argv": list(effect["argv"]),
            "boundary": effect["boundary"],
        }
        if "enforcement_receipt" in effect:
            value["enforcement_receipt"] = effect["enforcement_receipt"]
        self.observe(effect, value)

    def read_secret(self, effect_id: str) -> None:
        effect = self.effect(effect_id)
        if effect["kind"] != "read-environment" or not effect["secret"]:
            _raise("EFFECT-ENV-UNDECLARED", "effect is not a secret")
        self.observe(
            effect,
            {"type": "secret", "name": effect["name"], "present": True},
        )

    def finish(self) -> dict[str, Any]:
        self.outputs.sort(
            key=lambda item: (item["path"], item["sha256"], item["size_bytes"])
        )
        trace = {
            "schema": TRACE_SCHEMA,
            "plan_id": self.plan["id"],
            "plan_identity": _plan_identity(self.plan),
            "observations": self.observations,
            "dispositions": [
                {
                    "effect_id": effect["id"],
                    "disposition": (
                        "observed" if effect["id"] in self.consumed else "unused"
                    ),
                }
                for effect in self.plan["effects"]
            ],
            "outputs": self.outputs,
            "cache_eligible": _cache_eligible(
                self.plan, self.observations, self.enforcement
            ),
            "identity": "",
        }
        trace["identity"] = _trace_identity(trace)
        return trace


def validate_enforcement(receipt: dict[str, Any]) -> None:
    """Validate the independently bound synthetic enforcement receipt."""

    _exact_keys(
        receipt,
        {"schema", "id", "tool", "allowed_effects", "mechanism", "identity"},
        "EFFECT-ENFORCEMENT-FORGED",
    )
    if receipt["schema"] != ENFORCEMENT_SCHEMA:
        _raise("EFFECT-ENFORCEMENT-FORGED", "wrong receipt schema")
    _validate_id(receipt["id"], "enforcement")
    _validate_artifact(receipt["tool"])
    effects = receipt["allowed_effects"]
    if not effects or effects != sorted(set(effects)):
        _raise("EFFECT-ENFORCEMENT-WEAKENED", "invalid allowed-effect set")
    _exact_keys(receipt["mechanism"], {"name", "identity"}, "EFFECT-DECODE")
    _validate_id(receipt["mechanism"]["name"], "mechanism")
    _validate_digest(receipt["mechanism"]["identity"])
    material = {key: value for key, value in receipt.items() if key != "identity"}
    if domain_hash(ENFORCEMENT_SCHEMA, canonical_json(material)) != receipt["identity"]:
        _raise("EFFECT-ENFORCEMENT-FORGED", "receipt identity is invalid")


def _validate_effect(
    effect: dict[str, Any], enforcement: dict[str, Any] | None
) -> None:
    kind = effect.get("kind")
    common = {"id", "kind"}
    fields = {
        "read-file": common | {"path", "sha256", "size_bytes", "mode"},
        "require-absent": common | {"path"},
        "write-ephemeral": common | {"root"},
        "write-reviewed": common | {"path", "sha256", "size_bytes", "update_only"},
        "read-environment": common | {"name", "value_sha256", "secret"},
        "execute": common | {"tool", "argv", "boundary"},
        "network": common | {"mode"},
        "clock": common | {"mode"},
        "random": common | {"mode"},
    }.get(kind)
    if fields is None:
        _raise("EFFECT-PLAN-INVALID", "unknown effect kind")
    if kind == "execute" and effect.get("boundary") == "externally-enforced":
        if "enforcement_receipt" not in effect:
            _raise("EFFECT-ENFORCEMENT-MISSING", "receipt is absent")
        fields = fields | {"enforcement_receipt"}
    _exact_keys(effect, fields, "EFFECT-DECODE")
    try:
        _validate_id(effect["id"], "effect")
    except EffectFailure:
        _raise("EFFECT-ID-ALIAS", "invalid effect ID")
    if kind == "read-file":
        _validate_path(effect["path"])
        _validate_digest(effect["sha256"])
        if (
            not isinstance(effect["size_bytes"], int)
            or not 0 <= effect["size_bytes"] <= 16 * 1024 * 1024
            or not isinstance(effect["mode"], int)
            or not 0 <= effect["mode"] <= 0o7777
        ):
            _raise("EFFECT-PLAN-INVALID", "invalid file identity")
    elif kind == "require-absent":
        _validate_ephemeral_path(effect["path"])
    elif kind == "write-ephemeral":
        _validate_ephemeral_root(effect["root"])
    elif kind == "write-reviewed":
        _validate_path(effect["path"])
        _validate_digest(effect["sha256"])
        if effect["update_only"] is not True:
            _raise("EFFECT-WRITE-REVIEWED", "reviewed write is not update-only")
    elif kind == "read-environment":
        _validate_environment_name(effect["name"])
        if effect["secret"] is True and effect["value_sha256"] is None:
            return
        if effect["secret"] is False and isinstance(effect["value_sha256"], str):
            _validate_digest(effect["value_sha256"])
            return
        _raise("EFFECT-PLAN-INVALID", "ambiguous environment identity")
    elif kind == "execute":
        _validate_artifact(effect["tool"])
        _validate_argv(effect["argv"])
        boundary = effect["boundary"]
        if boundary not in {"mediated", "opaque", "externally-enforced"}:
            _raise("EFFECT-PLAN-INVALID", "unknown execution boundary")
        if boundary == "externally-enforced":
            if enforcement is None or "enforcement_receipt" not in effect:
                _raise("EFFECT-ENFORCEMENT-MISSING", "receipt is absent")
            if effect["enforcement_receipt"] != enforcement["identity"]:
                _raise("EFFECT-ENFORCEMENT-FORGED", "receipt identity differs")
            if enforcement["tool"] != effect["tool"] or enforcement[
                "allowed_effects"
            ] != [effect["id"]]:
                _raise("EFFECT-ENFORCEMENT-WEAKENED", "receipt scope differs")
    elif effect["mode"] != "denied":
        _raise("EFFECT-PLAN-INVALID", "ambient capability is not denied")


def _validate_workload(plan: dict[str, Any]) -> None:
    workload = plan["workload"]
    kind = workload.get("kind")
    fields = {
        "hidden-read": {"kind", "policy_effect"},
        "mutation-replay": {
            "kind",
            "target_effect",
            "mutant_effect",
            "witness_effect",
            "output_effect",
        },
        "distribution-build": {
            "kind",
            "payload_effects",
            "absent_effect",
            "output_effect",
        },
        "subprocess-boundary": {"kind", "execute_effect"},
        "secret-read": {"kind", "environment_effect"},
    }.get(kind)
    if fields is None:
        _raise("EFFECT-PLAN-INVALID", "unknown workload kind")
    _exact_keys(workload, fields, "EFFECT-DECODE")
    effect_kinds = {effect["id"]: effect["kind"] for effect in plan["effects"]}

    def require(effect_id: str, expected: str) -> None:
        if effect_kinds.get(effect_id) != expected:
            _raise("EFFECT-PLAN-INVALID", f"{effect_id} is not {expected}")

    if kind == "hidden-read":
        require(workload["policy_effect"], "read-file")
    elif kind == "mutation-replay":
        require(workload["target_effect"], "read-file")
        require(workload["mutant_effect"], "read-file")
        require(workload["witness_effect"], "read-file")
        require(workload["output_effect"], "write-ephemeral")
    elif kind == "distribution-build":
        payloads = workload["payload_effects"]
        if (
            not isinstance(payloads, list)
            or payloads != sorted(set(payloads))
            or len(payloads) != 2
        ):
            _raise("EFFECT-DISTRIBUTION-INVENTORY", "payloads are not an exact pair")
        for effect_id in payloads:
            require(effect_id, "read-file")
        require(workload["absent_effect"], "require-absent")
        require(workload["output_effect"], "write-ephemeral")
    elif kind == "subprocess-boundary":
        require(workload["execute_effect"], "execute")
    else:
        require(workload["environment_effect"], "read-environment")


def _cache_eligible(
    plan: dict[str, Any],
    observations: list[dict[str, Any]],
    enforcement: dict[str, Any] | None,
) -> bool:
    observed = {item["effect_id"] for item in observations}
    for effect in plan["effects"]:
        if effect["id"] not in observed:
            continue
        if effect["kind"] == "write-reviewed":
            return False
        if effect["kind"] == "read-environment" and effect["secret"]:
            return False
        if effect["kind"] == "execute" and effect["boundary"] == "opaque":
            return False
        if effect["kind"] == "execute" and effect["boundary"] == "externally-enforced":
            validate_effect_plan(plan, enforcement)
    return True


def _evaluate_attack(
    root: Path,
    plan: dict[str, Any],
    enforcement: dict[str, Any],
    attack: dict[str, Any],
) -> dict[str, Any]:
    _exact_keys(attack, {"id", "base", "code", "action"}, "EFFECT-DECODE")
    body_entered = not _is_preflight_attack(attack["action"])
    try:
        _run_attack(root, plan, enforcement, attack["action"])
    except EffectFailure as error:
        actual_code = error.code
    else:
        actual_code = "ACCEPTED"
    return {
        "id": attack["id"],
        "expected_code": attack["code"],
        "actual_code": actual_code,
        "exact": actual_code == attack["code"],
        "workload_body_entered": body_entered,
    }


def _is_preflight_attack(action: dict[str, Any]) -> bool:
    return action["kind"] in {
        "request-read",
        "request-environment",
        "request-network",
        "request-clock",
        "request-random",
        "request-reviewed-write",
        "request-ephemeral-write",
        "substitute-file-type",
        "request-execute",
        "substitute-executable",
        "substitute-argv",
        "remove-enforcement-receipt",
        "forge-enforcement-identity",
        "weaken-enforcement",
        "alias-effect-id",
        "duplicate-effect",
    }


def _run_attack(
    root: Path,
    plan: dict[str, Any],
    enforcement: dict[str, Any],
    action: dict[str, Any],
) -> None:
    kind = action["kind"]
    direct = {
        "request-read": "EFFECT-READ-UNDECLARED",
        "request-environment": "EFFECT-ENV-UNDECLARED",
        "request-reviewed-write": "EFFECT-WRITE-REVIEWED",
        "substitute-file-type": "EFFECT-PATH-SYMLINK",
        "request-execute": "EFFECT-EXEC-UNDECLARED",
    }
    if kind in direct:
        _raise(direct[kind], "requested authority rejected")
    if kind in {"request-network", "request-clock", "request-random"}:
        capability = kind.removeprefix("request-")
        effect = _find_effect(plan, action["effect_id"])
        if effect["kind"] != capability or effect["mode"] != "denied":
            _raise("EFFECT-PLAN-INVALID", "denial declaration is missing")
        _raise(f"EFFECT-{capability.upper()}-DENIED", "authority is denied")
    if kind == "request-ephemeral-write":
        effect = _find_effect(plan, action["effect_id"])
        if effect["kind"] != "write-ephemeral" or not _strict_descendant(
            effect["root"], action["path"]
        ):
            _raise("EFFECT-WRITE-ESCAPE", "write escaped boundary")
        return
    if kind == "substitute-executable":
        effect = _find_effect(plan, action["effect_id"])
        if effect["tool"]["sha256"] != action["sha256"]:
            _raise("EFFECT-EXEC-IDENTITY", "executable identity changed")
        return
    if kind == "substitute-argv":
        effect = _find_effect(plan, action["effect_id"])
        if effect["argv"] != action["argv"]:
            _raise("EFFECT-EXEC-ARGV", "arguments changed")
        return
    if kind == "remove-enforcement-receipt":
        mutated = deepcopy(plan)
        _execute_effect(mutated).pop("enforcement_receipt", None)
        validate_effect_plan(mutated, enforcement)
        return
    if kind == "forge-enforcement-identity":
        mutated = deepcopy(enforcement)
        mutated["identity"] = action["identity"]
        validate_enforcement(mutated)
        return
    if kind == "weaken-enforcement":
        mutated = deepcopy(enforcement)
        mutated["allowed_effects"] = action["allowed_effects"]
        try:
            validate_effect_plan(plan, mutated)
        except EffectFailure:
            _raise("EFFECT-ENFORCEMENT-WEAKENED", "receipt effect set weakened")
        return
    if kind == "alias-effect-id":
        try:
            _validate_id(action["alias"], "effect")
        except EffectFailure:
            _raise("EFFECT-ID-ALIAS", "effect alias is noncanonical")
        return
    if kind == "duplicate-effect":
        mutated = deepcopy(plan)
        mutated["effects"].append(deepcopy(_find_effect(mutated, action["effect_id"])))
        validate_effect_plan(mutated, enforcement)
        return
    trace = execute_effect_plan(root, plan, enforcement)
    if kind in {"forge-cache-eligible", "forge-exact-cache-eligible"}:
        trace["cache_eligible"] = True
    elif kind == "append-observation":
        trace["observations"].append(
            {
                "index": len(trace["observations"]),
                "effect_id": action["effect_id"],
                "kind": "read-file",
                "disposition": "observed",
                "value": {"type": "absence", "path": "ephemeral/unbound"},
            }
        )
    elif kind == "omit-unused-disposition":
        trace["dispositions"] = [
            item
            for item in trace["dispositions"]
            if item["effect_id"] != action["effect_id"]
        ]
    elif kind == "substitute-postimage":
        trace["outputs"][0]["sha256"] = sha256_bytes(action["content"].encode())
        trace["outputs"][0]["size_bytes"] = len(action["content"].encode())
    elif kind == "add-package-path":
        trace["outputs"].append(
            {"path": action["path"], "sha256": sha256_bytes(b"extra"), "size_bytes": 5}
        )
        trace["outputs"].sort(
            key=lambda item: (item["path"], item["sha256"], item["size_bytes"])
        )
    elif kind == "use-global-revision-invalidation":
        decision = derive_effect_invalidation(
            plan, trace, {action["changed_path"]: b"changed-only\n"}
        )
        if not decision["invalidated"]:
            _raise(
                "EFFECT-REVISION-OVERINVALIDATION",
                "global revision invalidates unrelated input",
            )
        return
    else:
        _raise("EFFECT-ATTACK-UNKNOWN", f"unknown attack {kind}")
    trace["identity"] = _trace_identity(trace)
    validate_effect_trace(root, plan, enforcement, trace)


def _validate_expected(
    root: Path,
    plans_doc: dict[str, Any],
    enforcement: dict[str, Any],
    expected: dict[str, Any],
    repetitions: int,
) -> None:
    _exact_keys(
        expected,
        {
            "schema",
            "repetitions",
            "enforcement_identity",
            "fixtures",
            "plans",
            "mutation_output",
            "distribution_output",
        },
        "EFFECT-DECODE",
    )
    if (
        expected["schema"] != "proofbound-research-effect-expected/1"
        or expected["repetitions"] != repetitions
        or expected["enforcement_identity"] != enforcement["identity"]
    ):
        _raise("EFFECT-EXPECTED-MISMATCH", "execution parameters differ")
    paths = [fixture["path"] for fixture in expected["fixtures"]]
    if paths != sorted(set(paths)):
        _raise("EFFECT-EXPECTED-MISMATCH", "fixture set is not canonical")
    for fixture in expected["fixtures"]:
        _validate_artifact(fixture)
        payload, mode = _read_regular(root, fixture["path"])
        if (
            sha256_bytes(payload) != fixture["sha256"]
            or len(payload) != fixture["size_bytes"]
            or mode != fixture["mode"]
        ):
            _raise("EFFECT-EXPECTED-MISMATCH", f"{fixture['path']} changed")
    actual = []
    for plan in plans_doc["plans"]:
        trace = execute_effect_plan(root, plan, enforcement)
        encoded = canonical_json(plan)
        actual.append(
            {
                "id": plan["id"],
                "identity": domain_hash(PLAN_SCHEMA, encoded),
                "canonical_bytes": len(encoded),
                "cache_eligible": trace["cache_eligible"],
            }
        )
    actual.sort(key=lambda item: item["id"])
    if actual != expected["plans"]:
        _raise("EFFECT-EXPECTED-MISMATCH", "plan identities differ")


def _validate_artifact(artifact: dict[str, Any]) -> None:
    _exact_keys(artifact, {"path", "sha256", "size_bytes", "mode"}, "EFFECT-DECODE")
    _validate_path(artifact["path"])
    _validate_digest(artifact["sha256"])
    if (
        not isinstance(artifact["size_bytes"], int)
        or not 0 <= artifact["size_bytes"] <= 16 * 1024 * 1024
        or not isinstance(artifact["mode"], int)
        or not 0 <= artifact["mode"] <= 0o7777
    ):
        _raise("EFFECT-PLAN-INVALID", "invalid artifact identity")


def _validate_id(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value.startswith("-")
        or value.endswith("-")
        or "--" in value
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
            for character in value
        )
    ):
        _raise("EFFECT-ID-INVALID", f"invalid {label} ID")


def _validate_digest(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        _raise("EFFECT-IDENTITY", "invalid SHA-256 identity")


def _validate_path(value: object) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 4096
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _raise("EFFECT-PATH-INVALID", "invalid path")
    path = PurePosixPath(value)
    reserved = {".git", ".proofbound", "target", "node_modules", "__pycache__"}
    if path.is_absolute() or any(
        part in {"", ".", ".."} | reserved for part in path.parts
    ):
        _raise("EFFECT-PATH-INVALID", "non-normal or reserved path")


def _validate_ephemeral_path(value: object) -> None:
    _validate_path(value)
    if not str(value).startswith("ephemeral/"):
        _raise("EFFECT-WRITE-ESCAPE", "path is not ephemeral")


def _validate_ephemeral_root(value: object) -> None:
    _validate_ephemeral_path(value)
    if str(value).endswith("/"):
        _raise("EFFECT-WRITE-ESCAPE", "invalid ephemeral root")


def _validate_environment_name(value: object) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
            for character in value
        )
    ):
        _raise("EFFECT-ENV-UNDECLARED", "invalid environment name")


def _validate_argv(argv: object) -> None:
    if not isinstance(argv, list) or not 1 <= len(argv) <= 64:
        _raise("EFFECT-EXEC-ARGV", "invalid argument vector")
    if any(
        not isinstance(argument, str)
        or not 1 <= len(argument) <= 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in argument)
        for argument in argv
    ):
        _raise("EFFECT-EXEC-ARGV", "invalid argument")


def _plan_identity(plan: dict[str, Any]) -> str:
    return domain_hash(PLAN_SCHEMA, canonical_json(plan))


def _trace_identity(trace: dict[str, Any]) -> str:
    material = {key: value for key, value in trace.items() if key != "identity"}
    return domain_hash(TRACE_SCHEMA, canonical_json(material))


def _read_regular(root: Path, relative: str) -> tuple[bytes, int]:
    _validate_path(relative)
    path = root / relative
    try:
        metadata = path.lstat()
    except OSError as error:
        _raise("EFFECT-IO", f"{relative}: {error}")
    if stat.S_ISLNK(metadata.st_mode):
        _raise("EFFECT-PATH-SYMLINK", f"{relative} is a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        _raise("EFFECT-PATH-TYPE", f"{relative} is not a file")
    return path.read_bytes(), stat.S_IMODE(
        metadata.st_mode
    ) if os.name == "posix" else 0o644


def _find_effect(plan: dict[str, Any], effect_id: str) -> dict[str, Any]:
    for effect in plan["effects"]:
        if effect["id"] == effect_id:
            return effect
    _raise("EFFECT-PLAN-INVALID", f"missing effect {effect_id}")


def _execute_effect(plan: dict[str, Any]) -> dict[str, Any]:
    for effect in plan["effects"]:
        if effect["kind"] == "execute":
            return effect
    _raise("EFFECT-PLAN-INVALID", "execute effect is missing")


def _strict_descendant(root: str, path: str) -> bool:
    return path.startswith(root + "/") and len(path) > len(root) + 1


def _exact_keys(value: object, expected: set[str], code: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        _raise(code, "record fields are not exact")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _raise("EFFECT-DECODE", str(error))
    if not isinstance(value, dict):
        _raise("EFFECT-DECODE", "top-level value is not an object")
    return value


def _raise(code: str, message: str) -> NoReturn:
    raise EffectFailure(code, message)


def main(argv: list[str] | None = None) -> int:
    """Execute the frozen corpus and write its canonical model report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: python -m proofbound.effects_research <root> <corpus-dir> <repetitions>",
            file=sys.stderr,
        )
        return 2
    try:
        repetitions = int(arguments[2])
        report = execute_effect_corpus(
            Path(arguments[0]), Path(arguments[1]), repetitions
        )
    except (EffectFailure, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
