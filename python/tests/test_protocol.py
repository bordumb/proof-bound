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
        "diagnostics": [],
        "evidence": {"schema": "proofbound-adapter-observation/1"},
        "inventory": [],
        "type": "response",
        "request_id": "a" * 32,
        "schema": "proofbound-adapter-protocol/1",
        "success": False,
    }
    with pytest.raises(ProtocolError, match="disagree"):
        AdapterResponse.parse(canonical_json(value))


def test_response_inventory_is_sorted_and_unique() -> None:
    response = AdapterResponse(
        "a" * 32,
        "python-test",
        True,
        {"schema": "proofbound-adapter-observation/1"},
        ("a", "b"),
        (),
    )
    assert AdapterResponse.parse(response.to_bytes()) == response
    value = json.loads(response.to_bytes())
    value["inventory"] = ["b", "a"]
    with pytest.raises(ProtocolError, match="sorted"):
        AdapterResponse.parse(canonical_json(value))
