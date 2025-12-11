use anyhow::Context;
use clap::Parser;
use givc::admin;
use givc::endpoint::TlsConfig;
use givc_common::pb::reflection::ADMIN_DESCRIPTOR;
use std::path::PathBuf;
use tonic::transport::Server;
use tracing::{debug, info};

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "givc-admin")]
#[command(about = "A givc admin", long_about = None)]
struct Cli {
    #[arg(
        long,
        help = "Additionally listen socket (addr:port, unix path, vsock:cid:port)"
    )]
    listen: Vec<tokio_listener::ListenerAddress>,

    #[arg(long, env = "TLS")]
    use_tls: bool,

    #[arg(long, env = "POLICY_UPDATER")]
    policy_updater: bool,

    #[arg(long, env = "CA_CERT")]
    ca_cert: Option<PathBuf>,

    #[arg(long, env = "HOST_CERT")]
    host_cert: Option<PathBuf>,

    #[arg(long, env = "HOST_KEY")]
    host_key: Option<PathBuf>,

    #[arg(long, env = "GIVC_MONITORING", default_value_t = true)]
    monitoring: bool,

    #[arg(long, env = "POLICY_URL")]
    policy_url: Option<PathBuf>,

    #[arg(long, env = "POLICY_UPDATE_INTERVAL")]
    policy_update_interval: Option<String>,

    #[arg(long, env = "POLICY_URL_ACCESS_TOKEN")]
    policy_access_token: Option<PathBuf>,

    #[arg(
        long,
        env = "SERVICES",
        use_value_delimiter = true,
        value_delimiter = ','
    )]
    services: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    givc::trace_init()?;

    let cli = Cli::parse();
    debug!("CLI is {:#?}", cli);

    let mut builder = Server::builder();

    let tls = if cli.use_tls {
        let tls = TlsConfig {
            ca_cert_file_path: cli.ca_cert.context("required")?,
            cert_file_path: cli.host_cert.context("required")?,
            key_file_path: cli.host_key.context("required")?,
            tls_name: None,
        };
        let tls_config = tls.server_config()?;
        builder = builder.tls_config(tls_config)?;
        Some(tls)
    } else {
        None
    };

    let reflect = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(ADMIN_DESCRIPTOR)
        .build_v1()
        .unwrap();

    let admin_service = admin::server::AdminService::new(tls, cli.monitoring);
    let admin_service_svc = admin::server::AdminServiceServer::new(admin_service.clone());

    let sys_opts = tokio_listener::SystemOptions::default();
    let user_opts = tokio_listener::UserOptions::default();

    info!("GGGGG givc-admin.{}", cli.policy_updater);
    let listener =
        tokio_listener::Listener::bind_multiple(&cli.listen, &sys_opts, &user_opts).await?;

    if (cli.policy_updater) {
        let policy_url = cli
            .policy_url
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let _ = cli.policy_access_token;
        let duration = cli
            .policy_update_interval
            .map(|p| std::time::Duration::from_secs(p.to_string().parse().unwrap()))
            .unwrap_or_default();
        let th_handle = admin::policy_updater::start_updater(
            admin_service.clone_inner(),
            policy_url,
            duration,
            "/etc/policies",
            "test_policy".to_string(),
        );
    }
    info!("GGGGG givc-adminnnnnnnnnnnnn.");
    builder
        .add_service(reflect)
        .add_service(admin_service_svc)
        .serve_with_incoming(listener)
        .await?;
    /* Cleanup */
    th_handle.abort();
    Ok(())
}
