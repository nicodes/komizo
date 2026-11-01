use anyhow::{Result, anyhow};
use komizo::workload::activation::*;
use serde_json::Value;
use std::time::{Duration, Instant};
struct Runtime {
    calls: Vec<String>,
    fault: String,
    stop_at: u64,
    stops: u64,
    ack: bool,
}
impl Runtime {
    fn step(&mut self, name: &str) -> Result<()> {
        self.calls.push(name.into());
        if self.fault == name {
            Err(anyhow!("fixture failure at {name}"))
        } else {
            Ok(())
        }
    }
}
impl ActivationRuntime for Runtime {
    fn verify(&mut self, ctx: &Context, _: &ActivationRequest) -> Result<()> {
        ctx.check()?;
        if self.fault == "reconciliation" {
            self.calls.push("verify".into());
            return Err(ActivationError::Reconciliation.into());
        };
        self.step("verify")
    }
    fn stopped(&mut self, ctx: &Context, _: &ActivationRequest) -> Result<bool> {
        ctx.check()?;
        self.stops += 1;
        self.step("stopped")?;
        Ok(self.stop_at > 0 && self.stops >= self.stop_at)
    }
    fn compose(&mut self, ctx: &Context, _: &ActivationRequest, action: &str) -> Result<()> {
        ctx.check()?;
        self.step(&format!("compose-{action}"))
    }
    fn reload_proxy(&mut self, ctx: &Context, _: &ActivationRequest) -> Result<()> {
        ctx.check()?;
        self.step("reload")
    }
    fn retain(&mut self, ctx: &Context, _: &ActivationRequest) -> Result<()> {
        ctx.check()?;
        self.step("retain")
    }
    fn ready(&mut self, ctx: &Context, _: &ActivationRequest) -> Result<()> {
        ctx.check()?;
        match self.fault.as_str() {
            "unspecified" => {
                self.calls.push("ready".into());
                Err(ActivationError::ReadinessUnspecified.into())
            }
            "owner-stopped" => {
                self.calls.push("ready".into());
                Err(ActivationError::Stopped.into())
            }
            _ => self.step("ready"),
        }
    }
    fn phase(&mut self, _: &ActivationRequest, phase: &str) -> Result<()> {
        if self.ack && matches!(phase, "failed" | "activation_failed" | "readiness_failed") {
            self.calls.push(format!("phase-{phase}"));
            Err(anyhow!("fixture acknowledgement failure"))
        } else {
            self.step(&format!("phase-{phase}"))
        }
    }
    fn abort_static(&mut self, ctx: &Context, _: &ActivationRequest) -> Option<Result<()>> {
        assert!(ctx.remaining().unwrap() <= Duration::from_secs(30));
        Some(self.step("abort-static"))
    }
}
#[test]
fn go_activation_trace_preserves_stop_intent_failure_fences_and_durable_acknowledgement() {
    let cases: Vec<Value> = serde_json::from_str(include_str!("data/go-activation.json")).unwrap();
    assert_eq!(cases.len(), 145);
    for (index, case) in cases.into_iter().enumerate() {
        let request: ActivationRequest = serde_json::from_value(case["request"].clone()).unwrap();
        let now = case["now"].as_str().unwrap().parse().unwrap();
        let error = |result: Result<()>| result.err().map(|e| e.to_string()).unwrap_or_default();
        if case["kind"] == "request" {
            assert_eq!(
                error(request.check_identity()),
                case["identity_error"],
                "case {index}"
            );
            assert_eq!(error(request.check(now)), case["error"], "case {index}");
            continue;
        }
        let mut runtime = Runtime {
            calls: vec![],
            fault: case["fault"].as_str().unwrap().into(),
            stop_at: case["stop_at"].as_u64().unwrap(),
            stops: 0,
            ack: case["ack"].as_bool().unwrap(),
        };
        let (mut output, result) = activate_with_clock(
            &Context::new(Instant::now() + Duration::from_secs(1800)),
            &request,
            &mut runtime,
            || now,
        );
        // Go's actual clock is nondeterministic; compare the entire trace and normalize only completion time.
        output.at = serde_json::from_value(case["output"]["at"].clone()).unwrap();
        assert_eq!(
            error(result),
            case["error"],
            "case {index} {}",
            case["fault"]
        );
        assert_eq!(
            serde_json::to_value(output).unwrap(),
            case["output"],
            "case {index}"
        );
        assert_eq!(
            serde_json::to_value(runtime.calls).unwrap(),
            case["calls"],
            "case {index}"
        );
    }
}
