use crate::wire_struct;
use anyhow::{Result, anyhow, ensure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
fn parse_cpu(raw: &str) -> Option<f64> {
    if !raw.contains('_') && !raw.to_ascii_lowercase().contains("0x") {
        return raw.parse().ok();
    }
    static FORMAT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let format=FORMAT.get_or_init(||regex::Regex::new(r"^[+-]?(?:(?:[0-9](?:_?[0-9])*(?:\.[0-9](?:_?[0-9])*)?|\.[0-9](?:_?[0-9])*|[0-9](?:_?[0-9])*\.)(?:[eE][+-]?[0-9](?:_?[0-9])*)?|0[xX]_?(?:[0-9a-fA-F](?:_?[0-9a-fA-F])*(?:\.[0-9a-fA-F](?:_?[0-9a-fA-F])*)?|\.[0-9a-fA-F](?:_?[0-9a-fA-F])*|[0-9a-fA-F](?:_?[0-9a-fA-F])*\.)[pP][+-]?[0-9](?:_?[0-9])*)$").unwrap());
    if !format.is_match(raw) {
        return None;
    }
    let raw = std::ffi::CString::new(raw.replace('_', "")).ok()?;
    let mut end = std::ptr::null_mut();
    let value = unsafe { libc::strtod(raw.as_ptr(), &mut end) };
    if unsafe { *end } != 0 {
        return None;
    }
    Some(value)
}
wire_struct!(ServiceBudget {memory_bytes:"memory_bytes":i64=>required,memory_reserve_bytes:"memory_reserve_bytes":i64=>optional,memory_swap_bytes:"memory_swap_bytes":i64=>required,milli_cpus:"milli_cpus":i64=>required});
wire_struct!(ResourcePolicy {aggregate_mode:"aggregate_mode":String=>optional,cgroup_parent:"cgroup_parent":String=>optional,default:"default":ServiceBudget=>required,services:"services":BTreeMap<String,ServiceBudget> =>optional,max_memory_bytes:"max_memory_bytes":i64=>required,max_memory_reserve_bytes:"max_memory_reserve_bytes":i64=>optional,max_memory_swap_bytes:"max_memory_swap_bytes":i64=>required,max_milli_cpus:"max_milli_cpus":i64=>required,startup_allowance_bytes:"startup_allowance_bytes":i64=>required});
impl ServiceBudget {
    pub fn check(&self) -> Result<()> {
        ensure!(
            self.memory_bytes >= 4 << 20
                && self.memory_bytes <= 64 << 30
                && self.memory_reserve_bytes >= 0
                && self.memory_reserve_bytes <= self.memory_bytes
                && self.memory_swap_bytes >= self.memory_bytes
                && self.memory_swap_bytes <= 128 << 30
                && (1..=64000).contains(&self.milli_cpus),
            "service budget requires finite memory, CPU and explicit bounded swap"
        );
        Ok(())
    }
}
impl ResourcePolicy {
    pub fn check(&self) -> Result<()> {
        ensure!(
            matches!(self.aggregate_mode.as_str(), "" | "sum" | "cgroup"),
            "unknown aggregate resource mode"
        );
        ensure!(
            self.aggregate_mode != "cgroup"
                || self.cgroup_parent.starts_with("/komizo-production/"),
            "cgroup aggregate mode requires an installed application allocation"
        );
        ensure!(
            self.cgroup_parent.is_empty()
                || self.cgroup_parent == "/komizo-production"
                || self
                    .cgroup_parent
                    .strip_prefix("/komizo-production/")
                    .is_some_and(super::identifier),
            "production cgroup must be host owned"
        );
        self.default.check()?;
        ensure!(
            self.max_memory_reserve_bytes >= 0
                && self.max_memory_reserve_bytes <= self.max_memory_bytes
                && self.default.memory_reserve_bytes <= self.max_memory_reserve_bytes,
            "service reserves need a finite protected parent reserve"
        );
        ensure!(
            !self.cgroup_parent.starts_with("/komizo-production/")
                || self.max_memory_reserve_bytes > 0 && self.default.memory_reserve_bytes > 0,
            "per-application serving budgets require explicit leaf and parent reserves"
        );
        ensure!(
            self.max_memory_bytes >= self.default.memory_bytes
                && self.max_memory_bytes <= 128 << 30
                && self.max_memory_swap_bytes >= self.max_memory_bytes
                && self.max_memory_swap_bytes <= 256 << 30
                && self.max_milli_cpus >= self.default.milli_cpus
                && self.max_milli_cpus <= 128000
                && self.startup_allowance_bytes >= 0
                && self.startup_allowance_bytes <= self.max_memory_bytes
                && self.services.len() <= 32,
            "invalid aggregate resource envelope"
        );
        for (name, budget) in &self.services {
            ensure!(super::identifier(name), "invalid service budget name");
            budget.check()?;
            ensure!(
                budget.memory_reserve_bytes <= self.max_memory_reserve_bytes,
                "service reserve exceeds its protected parent reserve"
            );
        }
        Ok(())
    }
}
fn scalar(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) if value.is_f64() => {
            let number = value.as_f64().unwrap();
            if number.abs() < 1e6 {
                number.to_string()
            } else {
                format!("{number:e}")
            }
        }
        _ => value.to_string(),
    }
}
pub fn memory_bytes(value: &Value) -> Result<i64> {
    let raw = scalar(value);
    let (digits, scale) = match raw.as_bytes().last() {
        Some(b'b' | b'B') => (&raw[..raw.len() - 1], 1),
        Some(b'k' | b'K') => (&raw[..raw.len() - 1], 1 << 10),
        Some(b'm' | b'M') => (&raw[..raw.len() - 1], 1 << 20),
        Some(b'g' | b'G') => (&raw[..raw.len() - 1], 1 << 30),
        _ => (&raw[..], 1),
    };
    ensure!(
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()),
        "memory must be positive whole bytes or b/k/m/g units"
    );
    let value = digits
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| anyhow!("memory must be finite and positive"))?;
    value
        .checked_mul(scale)
        .ok_or_else(|| anyhow!("memory amount overflow"))
}
pub fn bound_service(
    service: &mut Map<String, Value>,
    budget: &ServiceBudget,
) -> Result<(i64, i64, i64)> {
    let memory = service
        .get("mem_limit")
        .map(memory_bytes)
        .transpose()?
        .unwrap_or(budget.memory_bytes);
    let swap = service
        .get("memswap_limit")
        .map(memory_bytes)
        .transpose()?
        .unwrap_or(budget.memory_swap_bytes);
    let cpus = if let Some(raw) = service.get("cpus") {
        let value = parse_cpu(&scalar(raw))
            .filter(|value| value.is_finite() && *value > 0. && *value <= 64.)
            .ok_or_else(|| anyhow!("CPU quota must be finite and positive"))?;
        (value * 1000.).ceil() as i64
    } else {
        budget.milli_cpus
    };
    ensure!(
        memory <= budget.memory_bytes
            && memory >= budget.memory_reserve_bytes
            && swap <= budget.memory_swap_bytes
            && swap >= memory
            && cpus <= budget.milli_cpus,
        "service resource demand exceeds protected budget"
    );
    service.insert("mem_limit".into(), memory.into());
    if budget.memory_reserve_bytes > 0 {
        service.insert("mem_reservation".into(), budget.memory_reserve_bytes.into());
    }
    service.insert("memswap_limit".into(), swap.into());
    service.insert("cpus".into(), Value::from(cpus as f64 / 1000.));
    Ok((memory, swap, cpus))
}
pub fn bound_services(
    services: &mut Map<String, Value>,
    policy: Option<&ResourcePolicy>,
) -> Result<()> {
    let policy = policy.ok_or_else(|| {
        anyhow!("operator must configure a protected resource envelope before deployment")
    })?;
    let (mut memory, mut reserve, mut swap, mut cpus) = (0_i64, 0_i64, 0_i64, 0_i64);
    for (name, raw) in services {
        let service = raw
            .as_object_mut()
            .ok_or_else(|| anyhow!("{name}: invalid service definition"))?;
        if !policy.cgroup_parent.is_empty() {
            service.insert("cgroup_parent".into(), policy.cgroup_parent.clone().into());
        }
        let budget = policy.services.get(name).unwrap_or(&policy.default);
        let (m, ms, cpu) =
            bound_service(service, budget).map_err(|error| anyhow!("{name}: {error}"))?;
        memory = memory.checked_add(m).ok_or_else(|| {
            anyhow!("aggregate deployment resource demand exceeds protected envelope")
        })?;
        reserve = reserve
            .checked_add(budget.memory_reserve_bytes)
            .ok_or_else(|| {
                anyhow!("aggregate deployment resource demand exceeds protected envelope")
            })?;
        swap = swap.checked_add(ms).ok_or_else(|| {
            anyhow!("aggregate deployment resource demand exceeds protected envelope")
        })?;
        cpus = cpus.checked_add(cpu).ok_or_else(|| {
            anyhow!("aggregate deployment resource demand exceeds protected envelope")
        })?;
    }
    ensure!(
        memory
            .checked_add(policy.startup_allowance_bytes)
            .is_some_and(|value| value <= policy.max_memory_bytes)
            && reserve <= policy.max_memory_reserve_bytes
            && swap
                .checked_add(policy.startup_allowance_bytes)
                .is_some_and(|value| value <= policy.max_memory_swap_bytes)
            && cpus <= policy.max_milli_cpus,
        "aggregate deployment resource demand exceeds protected envelope"
    );
    Ok(())
}
