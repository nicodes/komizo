const USAGE: &str = "komizo-box -- the komizo agent, on the server\n\n  komizo-box rootd [--interval 60s] [--report PATH]\n  komizo-box platform apply|recover|inspect STAGE MANIFEST_SHA256\n  komizo-box report [--cached] [--volumes]\n  komizo-box poll --from UNIX --to UNIX\n  komizo-box monitor --from UNIX --to UNIX [--app NAME]\n  komizo-box serve [--socket PATH]\n  komizo-box app start|stop|restart|logs --app NAME\n  komizo-box preview up|down|resolve|ls|gc|configure|database\n  komizo-box workload SUBCOMMAND [FLAGS]\n  komizo-box enrol --api URL --token TOKEN\n  komizo-box agent\n  komizo-box unenrol\n  komizo-box preview-capabilities\n  komizo-box version\n";
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|s| matches!(s.as_str(), "release" | "application")) {
        if let Err(error) = komizo::deployment::commands::offline(&args, &mut std::io::stdout()) {
            eprintln!("komizo-box: {error}");
            std::process::exit(1);
        }
        return;
    }
    let Some(mode) = args.first() else {
        eprint!("{USAGE}");
        std::process::exit(2);
    };
    if matches!(mode.as_str(), "-h" | "--help" | "help") {
        eprint!("{USAGE}");
        return;
    }
    if !matches!(
        mode.as_str(),
        "rootd"
            | "platform"
            | "workload"
            | "report"
            | "poll"
            | "monitor"
            | "agent"
            | "serve"
            | "app"
            | "preview"
            | "preview-capabilities"
            | "enrol"
            | "unenrol"
            | "version"
    ) {
        eprintln!(
            "komizo-box: unknown mode {}\n\n{USAGE}",
            komizo::host::authority::quote(mode)
        );
        std::process::exit(2);
    }
    let context = komizo::runtime::signal_context();
    if let Err(error) = komizo::host::commands::run(&args, &context, &mut std::io::stdout()) {
        if error.downcast_ref::<komizo::flags::Help>().is_some() {
            eprint!("{USAGE}");
        }
        eprintln!("komizo-box: {error}");
        std::process::exit(1);
    }
}
