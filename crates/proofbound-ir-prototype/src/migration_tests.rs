use super::*;

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root should resolve")
}

fn corpus() -> std::path::PathBuf {
    Path::new("docs/experiments/0017-mixed-language-migration/corpus").to_owned()
}

fn observations(contract: &ForeignContract, cases: &ForeignCases) -> ForeignObservationEnvelope {
    let artifact = decode_hex(&contract.artifact.hex).expect("artifact should decode");
    let mut sets = Vec::new();
    for runtime in &contract.runtimes {
        for phase in ["baseline", "migrated"] {
            let calls = cases
                .cases
                .iter()
                .map(|case| {
                    let result = evaluate_case(&artifact, case).expect("case should evaluate");
                    let mut call = ForeignCall {
                        schema: FOREIGN_CALL_SCHEMA.to_owned(),
                        case_id: case.id.clone(),
                        phase: phase.to_owned(),
                        language: runtime.language.clone(),
                        contract_identity: contract.identity.clone(),
                        artifact_identity: (phase == "migrated")
                            .then(|| contract.artifact.identity.clone()),
                        operation: case.operation.clone(),
                        input_hex: case.input_hex.clone(),
                        input_value: case.input_value,
                        accepted: result.accepted,
                        value: result.value,
                        output_hex: result.output_hex,
                        error: result.error,
                        consumed: result.consumed,
                        identity: String::new(),
                    };
                    call.identity = call_identity(&call).expect("call should hash");
                    call
                })
                .collect();
            let mut set = ForeignObservationSet {
                schema: FOREIGN_OBSERVATIONS_SCHEMA.to_owned(),
                language: runtime.language.clone(),
                phase: phase.to_owned(),
                contract_identity: contract.identity.clone(),
                runtime: runtime.clone(),
                calls,
                identity: String::new(),
            };
            set.identity = observation_identity(&set).expect("observation should hash");
            sets.push(set);
        }
    }
    let mut envelope = ForeignObservationEnvelope {
        schema: OBSERVATION_ENVELOPE_SCHEMA.to_owned(),
        observations: sets,
        identity: String::new(),
    };
    envelope.identity = envelope_identity(&envelope).expect("envelope should hash");
    envelope
}

#[test]
fn mixed_graph_rejects_all_attacks_exactly() {
    let repository = root();
    let directory = corpus();
    let contract: ForeignContract =
        decode_control(&repository, &directory.join("contract.json")).expect("contract");
    let cases: ForeignCases =
        decode_control(&repository, &directory.join("cases.json")).expect("cases");
    let graphs: GraphTemplates =
        decode_control(&repository, &directory.join("graphs.json")).expect("graphs");
    let attacks: AttackCorpus =
        decode_control(&repository, &directory.join("attacks.json")).expect("attacks");
    let envelope = observations(&contract, &cases);
    let report = derive_report(&contract, &cases, &graphs, &envelope, &attacks)
        .expect("report should derive");
    assert_eq!(report.attacks.len(), 30);
    let mismatches = report
        .attacks
        .iter()
        .filter(|attack| !attack.exact)
        .collect::<Vec<_>>();
    assert!(mismatches.is_empty(), "attack mismatches: {mismatches:#?}");
    assert!(
        report
            .migrated
            .derivations
            .iter()
            .filter(|item| item.formal == "tested")
            .all(|item| item.formal != "proved")
    );
}
