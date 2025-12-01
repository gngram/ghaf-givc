use std::cmp::max;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use reqwest::{Client, StatusCode};
use tar::{Archive, Builder};
use tokio::time::sleep;
use tracing::{error, info};

const POLICY_STORE: &str = "/etc/policies";

pub type NewPolicyCallback =
    Arc<dyn Fn(&Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send + Sync>;

fn load_token_from_file(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    match fs::read_to_string(path) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        Err(e) => {
            error!("Failed to read token file {}: {e}", path.display());
            None
        }
    }
}

fn write_etag_to_file(path: &Path, etag: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, etag.trim())?;
    Ok(())
}

fn load_etag_from_file(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }

    match fs::read_to_string(path) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        Err(e) => {
            error!("Failed to read ETag file {}: {e}", path.display());
            None
        }
    }
}

pub fn monitor_policy_url(
    client: Client,
    admin_service: Arc<super::server::AdminServiceImpl>,
    policy_url: String,
    poll_interval: Duration,
    token_file: Option<PathBuf>,
    on_update: NewPolicyCallback,
) {
    tokio::spawn(async move {
        let _admin_service = admin_service;
        let mut token = None;

        if let Some(token_path) = token_file.as_ref() {
            token = load_token_from_file(token_path);
        }

        let policy_store = Path::new(POLICY_STORE);
        if let Err(e) = fs::create_dir_all(&policy_store) {
            error!("Failed to create policy store directory {POLICY_STORE}: {e}",);
            return;
        }

        let tag_file = policy_store.join("urltag.txt");
        let mut last_tag: Option<String> = load_etag_from_file(&tag_file);

        let failsleep = max(300, poll_interval.as_secs());
        let tmp_download = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to create temp dir: {e}");
                return;
            }
        };

        loop {
            let mut req = client.get(&policy_url);

            if let Some(ref t) = token {
                req = req.bearer_auth(t);
            }

            if let Some(tag) = last_tag.as_deref() {
                req = req.header(reqwest::header::IF_NONE_MATCH, tag);
            }

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    error!("Policy store poll HTTP error: {e:?}");
                    sleep(Duration::from_secs(failsleep)).await;
                    continue;
                }
            };

            if resp.status() == StatusCode::NOT_MODIFIED {
                if poll_interval.as_secs() > 0 {
                    sleep(poll_interval).await;
                    continue;
                }
                break;
            }

            if !resp.status().is_success() {
                error!("Policy store poll non-success status: {}", resp.status());
                sleep(Duration::from_secs(failsleep)).await;
                continue;
            }

            let new_etag = resp
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let body_bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    error!("Failed to read policy archive: {e:?}");
                    continue;
                }
            };

            let archive_path = tmp_download.path().join("policy.tar.gz");
            if let Err(e) = fs::write(&archive_path, &body_bytes) {
                error!(
                    "Failed to write policy archive to {}: {e}",
                    archive_path.display()
                );
                continue;
            }

            if let Err(e) = on_update(&archive_path) {
                error!("on_update callback error: {e:?}");
            }

            if let Some(ref et) = new_etag {
                last_tag = Some(et.clone());
                if let Err(e) = write_etag_to_file(&tag_file, et) {
                    error!("Failed to update ETag file {}: {e}", tag_file.display());
                }
            }

            if poll_interval.as_secs() > 0 {
                sleep(poll_interval).await;
            } else {
                break;
            }
        }
    });
}

fn handle_new_policy(admin_service: Arc<super::server::AdminServiceImpl>) -> NewPolicyCallback {
    Arc::new(move |source_archive: &Path| {
        let admin_service = admin_service.clone();
        let output_dir = Path::new(POLICY_STORE);

        let tar_gz = File::open(source_archive)?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);

        let mut vm_archives: HashMap<String, Builder<GzEncoder<File>>> = HashMap::new();

        if output_dir.exists() {
            info!("Cleaning policy store: {}", output_dir.display());
            fs::remove_dir_all(output_dir)?;
        }
        fs::create_dir_all(output_dir)?;

        info!("Unpacking new policies...");

        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.into_owned();

            let components: Vec<_> = entry_path
                .components()
                .map(|c| c.as_os_str().to_str().unwrap())
                .collect();

            if components.len() < 2 {
                continue;
            }

            /* We check index 1 because index 0 is the root folder name we want to discard */
            let policy_type = components[1];

            match policy_type {
                "opa" => {
                    /* Extract only opa directory to policy store, ignore root */
                    let relative_path: PathBuf = components.iter().skip(1).collect();
                    let target_path = output_dir.join(relative_path);

                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent)?;
                    }

                    entry.unpack(&target_path)?;
                    info!("Extracted: {:?}", target_path);
                }
                "vm-policies" => {
                    /* Skip the "vm-policies" if it has no children */
                    if components.len() < 3 {
                        continue;
                    }

                    let vm_name = components[2];

                    let builder = vm_archives.entry(vm_name.to_string()).or_insert_with(|| {
                        let parent_path = output_dir.join("vm-policies");

                        std::fs::create_dir_all(&parent_path)
                            .expect("Failed to create vm-policies dir");

                        let archive_path = parent_path.join(format!("{}.tar.gz", vm_name));
                        info!("Creating Archive: {:?}", archive_path);

                        let file =
                            File::create(archive_path).expect("Failed to create archive file");
                        let enc = GzEncoder::new(file, Compression::default());
                        Builder::new(enc)
                    });

                    /* Prepare header for the new archive */
                    let mut header = entry.header().clone();
                    let path_inside_tar: PathBuf = components.iter().skip(2).collect();
                    builder.append_data(&mut header, path_inside_tar, &mut entry)?;
                }
                _ => {
                    info!("Skipping: {:?}", entry_path);
                }
            }
        }

        /* archive all */
        for (name, mut builder) in vm_archives {
            builder.finish()?;
            info!("Finished archive for: {}", name);
            let admin_service = admin_service.clone();
            tokio::spawn(async move {
                let archive_path = output_dir
                    .join("vm-policies")
                    .join(format!("{}.tar.gz", name));
                if let Err(e) = admin_service.push_policy_update(&name, &archive_path).await {
                    error!("Failed to push policy update to {}: {}", name, e);
                }
            });
        }

        Ok(())
    })
}

pub async fn start_updater(
    admin_service: Arc<super::server::AdminServiceImpl>,
    policy_url: String,
    poll_interval: Duration,
    token_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();

    info!("GGGG Policy Repo URL: {}", policy_url);
    info!("GGGG Poll interval: {}", poll_interval.as_secs());
    if let Some(path) = token_file.as_ref() {
        info!("GGGG URL access token: {}", path.display());
    }

    let callback = handle_new_policy(admin_service.clone());

    monitor_policy_url(
        client,
        admin_service,
        policy_url,
        poll_interval,
        token_file,
        callback,
    );
    Ok(())
}
