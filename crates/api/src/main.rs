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
    let config = Config::parse(&args)?;
    let parent = config.parent_pid;
    let listener = tokio::net::TcpListener::bind((config.bind.as_str(), config.port)).await?;
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let ui = komizo_api::ui::Ui::new(config, stop.clone());
    println!("komizo UI on http://{}", listener.local_addr()?);
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
