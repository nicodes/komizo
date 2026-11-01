use super::{emit, enter_read_budget, parse};
use crate::{
    flags::Flag,
    host::{observer::Observer, paths::*, store::*, *},
    workload::activation::Context,
};
use anyhow::{Result, ensure};
use std::{io::Write, path::Path};
pub fn run(mode: &str, args: &[String], ctx: &Context, output: &mut dyn Write) -> Result<()> {
    let probe = Probe::default();
    match mode {
        "report" => {
            let flags = parse(
                &[
                    Flag::boolean("volumes", false),
                    Flag::boolean("cached", false),
                    Flag::text("report", REPORT_PATH),
                ],
                args,
                false,
            )?;
            if flags.boolean("cached") {
                return emit(output, &read_report(Path::new(flags.text("report")))?);
            }
            enter_read_budget()?;
            let mut report = Observer::new(&probe, || ctx.check().is_err())
                .report(crate::runtime::VERSION, None);
            if flags.boolean("volumes") && report.server.ready() {
                report.system.volumes = Observer::new(&probe, || ctx.check().is_err())
                    .volumes("")
                    .into();
            }
            emit(output, &report)
        }
        "poll" => {
            let flags = parse(
                &[Flag::integer("from", 0), Flag::integer("to", 0)],
                args,
                false,
            )?;
            enter_read_budget()?;
            let report = Observer::new(&probe, || ctx.check().is_err())
                .report(crate::runtime::VERSION, None);
            let mut poll = Poll {
                v: REPORT_VERSION,
                report,
                ..Default::default()
            };
            if flags.integer("from") != 0 && flags.integer("to") != 0 {
                poll.metrics = probe.metrics(flags.integer("from"), flags.integer("to"));
            }
            emit(output, &poll)
        }
        "monitor" => {
            let flags = parse(
                &[
                    Flag::integer("from", 0),
                    Flag::integer("to", 0),
                    Flag::text("app", ""),
                    Flag::text("history", HISTORY_PATH),
                ],
                args,
                false,
            )?;
            let (from, to) = (flags.integer("from"), flags.integer("to"));
            ensure!(from != 0 && to != 0, "both --from and --to are required");
            enter_read_budget()?;
            let mut monitor = Monitor {
                v: REPORT_VERSION,
                metrics: probe.metrics(from, to),
                history: read_samples(Path::new(flags.text("history")), from, to)
                    .ok()
                    .flatten()
                    .unwrap_or_default()
                    .into(),
                ..Default::default()
            };
            if !flags.text("app").is_empty() {
                monitor.volumes = Observer::new(&probe, || ctx.check().is_err())
                    .volumes(flags.text("app"))
                    .into();
            }
            emit(output, &monitor)
        }
        _ => unreachable!(),
    }
}
