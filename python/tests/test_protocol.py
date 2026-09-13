import json

import pytest

from proofbound import AdapterRequest, AdapterResponse, ProtocolError, canonical_json


def test_request_round_trip_is_canonical_and_closed() -> None:
    request = AdapterRequest("a" * 32, "python-test", "check", ".", {"id": "unit"})
    encoded = request.to_bytes()
    assert not encoded.endswith(b"\n")
    assert AdapterRequest.parse(encoded) == request
    value = json.loads(encoded)
    value["unknown"] = True
    with pytest.raises(ProtocolError, match="missing or unknown"):
        AdapterRequest.parse(canonical_json(value))


def test_noncanonical_message_is_rejected() -> None:
    request = AdapterRequest("a" * 32, "python-test", "check", ".", {"id": "unit"})
    with pytest.raises(ProtocolError, match="not canonical"):
        AdapterRequest.parse(request.to_bytes() + b"\n")


def test_failed_response_cannot_carry_evidence() -> None:
    value = {
        "adapter": "python-test",
        "diagnostics": [{"code": "PB-PYTHON-0001", "message": "failed"}],
        "evidence": {"schema": "proofbound-adapter-observation/3"},
        "inventory": [],
        "type": "response",
        "request_id": "a" * 32,
        "schema": "proofbound-adapter-protocol/2",
        "success": False,
    }
    with pytest.raises(ProtocolError, match="failed response"):
        AdapterResponse.parse(canonical_json(value))


def test_failed_response_requires_empty_inventory_and_a_diagnostic() -> None:
    value = {
        "adapter": "python-test",
        "diagnostics": [],
        "evidence": None,
        "inventory": [],
        "type": "response",
        "request_id": "a" * 32,
        "schema": "proofbound-adapter-protocol/2",
        "success": False,
    }
    with pytest.raises(ProtocolError, match="at least one diagnostic"):
        AdapterResponse.parse(canonical_json(value))

    value["diagnostics"] = [{"code": "PB-PYTHON-0001", "message": "failed"}]
    value["inventory"] = ["must-not-survive-failure"]
    with pytest.raises(ProtocolError, match="empty inventory"):
        AdapterResponse.parse(canonical_json(value))

    value["inventory"] = []
    response = AdapterResponse.parse(canonical_json(value))
    assert AdapterResponse.parse(response.to_bytes()) == response


def test_successful_null_evidence_responses_are_protocol_valid() -> None:
    doctor = AdapterResponse("a" * 32, "python-test", True, None, (), ())
    assert AdapterResponse.parse(doctor.to_bytes()) == doctor

    inventory = AdapterResponse(
        "a" * 32, "python-test", True, None, ("registered-target",), ()
    )
    assert AdapterResponse.parse(inventory.to_bytes()) == inventory


def test_response_serializer_rejects_an_invalid_v2_failure() -> None:
    response = AdapterResponse(
        "a" * 32,
        "python-test",
        False,
        None,
        (),
        (),
    )
    with pytest.raises(ProtocolError, match="at least one diagnostic"):
        response.to_bytes()


def test_response_inventory_is_sorted_and_unique() -> None:
    response = AdapterResponse(
        "a" * 32,
        "python-test",
        True,
        {"schema": "proofbound-adapter-observation/3"},
        ("a", "b"),
        (),
    )
    assert AdapterResponse.parse(response.to_bytes()) == response
    value = json.loads(response.to_bytes())
    value["inventory"] = ["b", "a"]
    with pytest.raises(ProtocolError, match="sorted"):
        AdapterResponse.parse(canonical_json(value))

    value["inventory"] = [" \t"]
    with pytest.raises(ProtocolError, match="non-empty"):
        AdapterResponse.parse(canonical_json(value))
