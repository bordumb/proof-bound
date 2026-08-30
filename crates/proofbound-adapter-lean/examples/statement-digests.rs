use std::{env, fs, io::Read, process::ExitCode};

use proofbound_adapter_lean::{
    model::{AuditOutput, LEAN_AUDIT_SCHEMA},
    wire::statement_digest,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let path = env::args()
        .nth(1)
        .ok_or_else(|| "usage: statement-digests AUDIT.json|-".to_owned())?;
    if env::args().nth(2).is_some() {
        return Err("usage: statement-digests AUDIT.json|-".to_owned());
    }
    let bytes = if path == "-" {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read stdin: {error}"))?;
        bytes
    } else {
        fs::read(&path).map_err(|error| format!("cannot read {path}: {error}"))?
    };
    let audit: AuditOutput =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid audit JSON: {error}"))?;
    if audit.schema != LEAN_AUDIT_SCHEMA || audit.statement_encoding != "lean-expr-cbor/1" {
        return Err("unsupported Lean audit schema or statement encoding".to_owned());
    }
    for claim in audit.claims {
        let digest = statement_digest(&claim.expr_wire)
            .map_err(|error| format!("cannot encode {}: {error}", claim.declaration))?;
        println!(
            "{}\t{}\tsha256:{}\t{}",
            claim.claim_id,
            claim.declaration,
            digest.to_hex(),
            claim.axioms.join(",")
        );
    }
    Ok(())
}
