use komizo_api::{
    config::Config,
    error::{Result, fail},
};
use std::time::Duration;
#[tokio::main]
async fn main() {
    httpcontract::init_logging();
    if let Err(error) = run().await {
        eprintln!("komizo UI: {}", error.message);
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "komizo-api ui --host HOST --owner-client ABSOLUTE_PATH [--identity PATH] [--bind LOOPBACK_IP] [--port N]"
        );
        return Ok(());
    }
    let mut config = Config::parse(&args)?;
    if config.parent_pid.is_none() {
        return Err(komizo_api::error::invalid(
            "launch the owner UI using komizo ui",
        ));
    }
    let mut input: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(0, &mut input) } != 0 || input.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(komizo_api::error::invalid(
            "owner UI requires its private launch pipe",
        ));
    }
    let parent = config.parent_pid;
    let listener = tokio::net::TcpListener::bind((config.bind.as_str(), config.port)).await?;
    config.port = listener.local_addr()?.port();
    let session = komizo_api::session::Session::receive(std::io::stdin().lock(), &config)?;
    let launcher = session.launcher_url();
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let ui = komizo_api::ui::Ui::new(config, session, stop.clone());
    println!("Open the owner UI: {launcher}");
    let server = tokio::spawn(komizo_api::server::run(listener, ui.router(), stopping));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _=tokio::signal::ctrl_c()=>{}, _=term.recv()=>{},
        _=async { if let Some(pid)=parent { loop { tokio::time::sleep(Duration::from_millis(250)).await;
            if unsafe{libc::getppid()} as u32 != pid { break; }
        }} else { std::future::pending::<()>().await; }}=>{},
        _=async { while !server.is_finished() { tokio::time::sleep(Duration::from_millis(100)).await; }}=>{}
    }
    ui.shutdown().await;
    server
        .await
        .map_err(|_| fail(500, "UI listener failed"))??;
    Ok(())
}
