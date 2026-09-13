programme "python-inventory" ecosystem "python"

defaults "python-common"
claims = ["PY-RESERVATION-001"]
tier = 0
assumptions = ["PY-RUNTIME-001"]
inputs = ["pyproject.toml","requirements-dev.txt","src/inventory_service/__init__.py","src/inventory_service/reservations.py","tests/test_reservations.py"]
outputs = []
environment_allowlist = ["PATH"]
resource_budget = {"time_seconds":60,"disk_bytes":268435456,"memory_bytes":536870912}
end

claim "PY-RESERVATION-001"
title = "Accepted reservations remain within supplied capacity"
statement = "For the registered examples and seeded generated inputs, an accepted reservation never produces committed inventory above the supplied capacity."
public_language = "Exact pytest examples, a registered mutation witness, a seeded Hypothesis property, mypy, and an independent vector checker support the registered reservation behavior."
subject = "python:proofbound-python-inventory::inventory_service.reservations.reserve"
profile = "ledger"
tier = 1
primary_linkage = "model-only"
evidence = ["example-test:reservation-example","mutation-witness:accept-over-cap-mutant","property-test:reservation-property","static-check:reservation-types","independent-check:reservation-vectors"]
assumptions = ["PY-RUNTIME-001"]
premises = []
open_obligations = []
out_of_scope = ["The Hypothesis run is not an exhaustive search or an unbounded theorem.","Dynamic dispatch, monkeypatching, import order, and interpreter correctness are not modeled.","No source-refinement or artifact binding connects this claim to a deployed interpreter process."]
source_roots = ["src/inventory_service/reservations.py"]
end

evidence python-example "reservation-example" using "python-common"
expected_inventory = ["test_reservations::test_rejects_request_beyond_remaining_capacity"]
operation = {"type":"pytest","manifest":"pyproject.toml","targets":["test_rejects_request_beyond_remaining_capacity"],"paths":["tests/test_reservations.py"],"plugins":[]}
end

evidence python-property "reservation-property" using "python-common"
expected_inventory = ["test_reservations::test_accepted_reservation_never_exceeds_capacity"]
operation = {"type":"pytest","manifest":"pyproject.toml","targets":["test_accepted_reservation_never_exceeds_capacity"],"paths":["tests/test_reservations.py"],"plugins":["_hypothesis_pytestplugin"]}
property = {"schema":"proofbound-python-property/1","framework":"hypothesis","seed":4025493768}
end

end
