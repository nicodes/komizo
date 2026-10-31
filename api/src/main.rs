use komizo_api::{
    config::{Authority, Config},
    error::{Result, fail},
    store,
};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    time::Duration,
};
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("komizo API: {}", error.message);
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|s| s == "--help" || s == "-h") {
        println!(
            "komizo-api ui|serve|preview-ask [--bind IP] [--port N] [--socket PATH] [--config PATH]"
        );
        return Ok(());
    }
    let config = Config::parse(&args)?;
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let parent = config.parent_pid;
    let mut ui_owner = None;
    let server = if config.mode == "serve" {
        let Some(authority) = Authority::load(&config.credential)? else {
            eprintln!("this box has no registry key, so it serves nothing.");
            return Ok(());
        };
        match std::fs::symlink_metadata(&config.socket) {
            Ok(meta) => {
                if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
                    return Err(fail(503, "socket path is not owned by this API"));
                }
                if tokio::net::UnixStream::connect(&config.socket)
                    .await
                    .is_ok()
                {
                    return Err(fail(503, "API socket is already in use"));
                }
                std::fs::remove_file(&config.socket)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = tokio::net::UnixListener::bind(&config.socket)?;
        std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o660))?;
        let app = komizo_api::http::Monitor::new(authority, config.paths.clone());
        tokio::spawn(komizo_api::server::run_unix(
            listener,
            app.router(),
            stopping,
        ))
    } else {
        let app = if config.mode == "ui" {
            let ui = komizo_api::ui::Ui::new(config.clone(), stop.clone());
            let router = ui.router();
            ui_owner = Some(ui);
            router
        } else {
            let body = match store::bytes(&config.preview_knob, 1 << 20) {
                Ok(raw) => {
                    String::from_utf8(raw).map_err(|_| fail(503, "preview policy is unreadable"))?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e.into()),
            };
            let policy = std::sync::Arc::new(komizo_api::preview::Policy::parse(&body));
            axum::Router::new().fallback(move |request: axum::extract::Request| {
                let policy = policy.clone();
                async move {
                    let query = request.uri().query().unwrap_or("");
                    let pairs: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();
                    let domain = pairs
                        .iter()
                        .find(|(key, _)| key == "domain")
                        .map_or("", |(_, value)| value.as_ref());
                    if policy.allows(domain) {
                        axum::http::StatusCode::OK
                    } else {
                        axum::http::StatusCode::FORBIDDEN
                    }
                }
            })
        };
        let listener = tokio::net::TcpListener::bind((config.bind.as_str(), config.port)).await?;
        println!(
            "komizo {} on http://{}",
            config.mode,
            listener.local_addr()?
        );
        tokio::spawn(komizo_api::server::run(listener, app, stopping))
    };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{},_=async{if let Some(pid)=parent{loop{tokio::time::sleep(Duration::from_millis(250)).await;if unsafe{libc::getppid()}as u32!=pid{break;}}}else{std::future::pending::<()>().await;}}=>{},_=async{while !server.is_finished(){tokio::time::sleep(Duration::from_millis(100)).await;}}=>{}}
    let _ = stop.send(true);
    if let Some(ui) = ui_owner {
        ui.shutdown().await;
    }
    server
        .await
        .map_err(|_| fail(500, "API listener failed"))??;
    Ok(())
}
