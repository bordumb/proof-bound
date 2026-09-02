mod property;

use std::{cell::Cell, fs, path::PathBuf, process::ExitCode};

use proofbound_evidence::canonical_json;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed, TestCaseError, TestError, TestRunner};
use serde::Serialize;

use crate::property::{
    RequestSample, accepted_transfer_respects_cap, deliberately_false, strategy,
};

#[derive(Serialize)]
struct ProbeResult {
    schema: &'static str,
    framework: Framework,
    registered: RegisteredExecution,
    positive: RunProbe,
    counterexample: RunProbe,
    public_api_gap: PublicApiGap,
}

#[derive(Serialize)]
struct Framework {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct RegisteredExecution {
    seed: u64,
    successful_cases: u32,
    rng_algorithm: &'static str,
    persistence: &'static str,
    max_shrink_iterations: u32,
    max_local_rejects: u32,
    max_global_rejects: u32,
}

#[derive(Serialize)]
struct RunProbe {
    typed_result: &'static str,
    predicate_invocations: u64,
    minimal_counterexample: Option<RequestSample>,
}

#[derive(Serialize)]
struct PublicApiGap {
    successful_case_counter: &'static str,
    local_reject_counter: &'static str,
    global_reject_counter: &'static str,
    accepted_shrink_counter: &'static str,
    consequence: &'static str,
}

#[derive(Clone, Copy)]
enum ProbeAlgorithm {
    ChaCha,
    XorShift,
}

impl ProbeAlgorithm {
    fn parse(value: Option<&str>) -> Result<Self, &'static str> {
        match value.unwrap_or("chacha") {
            "chacha" => Ok(Self::ChaCha),
            "xorshift" => Ok(Self::XorShift),
            _ => Err("RNG algorithm must be chacha or xorshift"),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ChaCha => "chacha",
            Self::XorShift => "xorshift",
        }
    }

    const fn runner(self) -> RngAlgorithm {
        match self {
            Self::ChaCha => RngAlgorithm::ChaCha,
            Self::XorShift => RngAlgorithm::XorShift,
        }
    }
}

fn config(algorithm: ProbeAlgorithm) -> Config {
    Config {
        cases: 100,
        failure_persistence: None,
        rng_algorithm: algorithm.runner(),
        rng_seed: RngSeed::Fixed(424242),
        max_shrink_iters: 10_000,
        max_local_rejects: 1_000,
        max_global_rejects: 1_000,
        ..Config::default()
    }
}

fn run_positive(algorithm: ProbeAlgorithm) -> RunProbe {
    let calls = Cell::new(0_u64);
    let mut runner = TestRunner::new(config(algorithm));
    runner
        .run(&strategy(), |sample| {
            calls.set(calls.get() + 1);
            if accepted_transfer_respects_cap(&sample) {
                Ok(())
            } else {
                Err(TestCaseError::fail("registered property failed"))
            }
        })
        .expect("the positive holdout property must pass");
    RunProbe {
        typed_result: "passed",
        predicate_invocations: calls.get(),
        minimal_counterexample: None,
    }
}

fn run_counterexample(algorithm: ProbeAlgorithm) -> RunProbe {
    let calls = Cell::new(0_u64);
    let mut runner = TestRunner::new(config(algorithm));
    let error = runner
        .run(&strategy(), |sample| {
            calls.set(calls.get() + 1);
            if deliberately_false(&sample) {
                Ok(())
            } else {
                Err(TestCaseError::fail("deliberately false"))
            }
        })
        .expect_err("the false holdout property must fail");
    let minimal_counterexample = match error {
        TestError::Fail(_, sample) => Some(sample),
        TestError::Abort(reason) => panic!("unexpected proptest abort: {reason}"),
    };
    RunProbe {
        typed_result: "counterexample",
        predicate_invocations: calls.get(),
        minimal_counterexample,
    }
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let Some(output) = arguments.next().map(PathBuf::from) else {
        eprintln!(
            "usage: proofbound-exp0007-proptest-probe <exclusive-output.json> [chacha|xorshift]"
        );
        return ExitCode::from(2);
    };
    let algorithm = match ProbeAlgorithm::parse(arguments.next().as_deref()) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    if arguments.next().is_some() {
        eprintln!("unexpected extra argument");
        return ExitCode::from(2);
    }
    let result = ProbeResult {
        schema: "proofbound-research-proptest-observation-probe/1",
        framework: Framework {
            name: "proptest",
            version: "1.11.0",
        },
        registered: RegisteredExecution {
            seed: 424242,
            successful_cases: 100,
            rng_algorithm: algorithm.name(),
            persistence: "disabled",
            max_shrink_iterations: 10_000,
            max_local_rejects: 1_000,
            max_global_rejects: 1_000,
        },
        positive: run_positive(algorithm),
        counterexample: run_counterexample(algorithm),
        public_api_gap: PublicApiGap {
            successful_case_counter: "private",
            local_reject_counter: "private",
            global_reject_counter: "private",
            accepted_shrink_counter: "not-exposed",
            consequence: "predicate invocations cannot be partitioned into fresh attempts, rejections, and shrink replays through the stable typed API",
        },
    };
    let bytes = canonical_json(&result).expect("bounded probe result must canonicalize");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .and_then(|mut file| std::io::Write::write_all(&mut file, &bytes))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("failed to write exclusive result: {error}");
            ExitCode::from(1)
        }
    }
}
