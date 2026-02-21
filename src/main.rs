mod api;
mod crypto;

use api::AppState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Enable HTTPS using a self-signed or provided certificate
    #[arg(long)]
    https: bool,
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let vaults_dir = std::path::PathBuf::from("./vaults");
    tokio::fs::create_dir_all(&vaults_dir).await.unwrap();

    let state = AppState {
        unlocked_vaults: Arc::new(RwLock::new(HashMap::new())),
        vaults_dir,
    };

    let app = api::router(state);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 3000));

    if cli.https {
        let cert_path = "cert.pem";
        let key_path = "key.pem";

        if !std::path::Path::new(cert_path).exists() || !std::path::Path::new(key_path).exists() {
            tracing::info!("Generating self-signed certificate for HTTPS...");
            let cert =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                    .unwrap();
            std::fs::write(cert_path, cert.cert.pem()).unwrap();
            std::fs::write(key_path, cert.signing_key.serialize_pem()).unwrap();
        }

        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .unwrap();

        tracing::info!("listening on https://{}", addr);

        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        tracing::info!("listening on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}
