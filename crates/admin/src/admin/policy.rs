use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info};

use crate::policyadmin_api::policy_manager::PolicyManager;
use crate::policyadmin_api::policy_repo::PolicyRepository;
use crate::utils::json::JsonNode;

pub async fn start_policy_repo_monitor(
    admin_service: Arc<super::server::AdminServiceImpl>,
    policyroot: &Path,
    configs: &Path,
) -> thread::JoinHandle<()> {
    let policyroot = policyroot.to_path_buf();
    info!("policy-monitor: starting policy monitor...");

    thread::spawn(move || {
        info!("policy-monitor: thread spawned successfully");
        let policy_path = policyroot.join("data").join("vm-policies");

        let policy_manager = match PolicyManager::new(&policy_path, &configs, admin_service.clone())
        {
            Ok(pm) => pm,
            Err(e) => {
                error!("policy-monitor: failed to initialize policy manager: {}", e);
                return;
            }
        };

        let conf = match JsonNode::from_file(configs) {
            Ok(c) => c,
            Err(e) => {
                error!("policy-monitor: failed to load config file: {}", e);
                return;
            }
        };

        let source_type = conf.get_field(&["source", "type"]);
        let policy_url = conf.get_field(&["source", "url"]);
        let branch = conf.get_field(&["source", "branch"]);
        let poll_interval = conf
            .get_field(&["source", "poll_interval_secs"])
            .parse::<u64>()
            .unwrap_or(60);

        if source_type == "git" {
            let policy_dir = policyroot.join("data");
            let mut policy_repo = match PolicyRepository::new(policy_url, branch, &policy_dir) {
                Ok(u) => u,
                Err(e) => {
                    error!(
                        "policy-monitor: failed to initialize policy repository: {}",
                        e
                    );
                    return;
                }
            };
            let head_str = policy_repo
                .current_head()
                .map(|h| h.to_string())
                .unwrap_or_else(|| "UNKNOWN".into());

            info!("policy-monitor: current HEAD is: {}", head_str);
            /*
             * Duration between policy updates,
             * if defined to zero policy update will take place once after boot.
             * it will check updates every five minutes by default.
             */
            let wait_time = if poll_interval == Duration::ZERO {
                Duration::from_secs(300)
            } else {
                poll_interval
            };
            let mut update_err = false;
            loop {
                info!("policy-monitor: --- checking for policy updates ---");
                match policy_repo.get_update() {
                    Ok(true) => {
                        let new_head = updater
                            .current_head()
                            .ok_or("policy-manager: Failed to get current head.")?;
                        let old_head = updater
                            .old_head()
                            .ok_or("policy-manager: Failed to get old head.")?;

                        info!(
                            "policy-manager: Policy update found! Fetched changes from {} to {}",
                            old_head, new_head
                        );

                        let changes =
                            updater.get_change_set(&old_head.to_string(), &new_head.to_string())?;
                        if !changes.is_empty {
                            if let Err(e) = policy_manager.update_changeset_to_vms(&changes) {
                                error!("policy-monitor: policy update processing failed: {}", e);
                                update_err = true;
                            } else {
                                if poll_interval == Duration::ZERO {
                                    return;
                                }
                            }
                        } else {
                            policy_manager.update_all_vms();
                            if poll_interval == Duration::ZERO {
                                return;
                            }
                        }
                    }
                    Ok(false) => info!("policy-monitor: repository is already up-to-date."),
                    Err(e) => {
                        error!("policy-monitor: error during get_update(): {}", e);
                        update_err = true;
                    }
                }

                if update_err {
                    let _ = policy_repo.ensure_clone();
                    let new_head = policy_repo
                        .current_head()
                        .map(|h| h.to_string())
                        .unwrap_or_else(|| "UNKNOWN".into());

                    update_err = false;
                }

                thread::sleep(wait_time);
            }
        }

        match policy_manager.ensure_policy_cache(&head_str) {
            Ok(updated) => {
                if updated {
                    let _ = policy_manager.update_all_vms(&head_str);
                } else {
                    info!("policy-monitor: policy cache is up-to-date.");
                }
            }
            Err(e) => {
                error!("policy-monitor: policy cache update failed: {}", e);
            }
        }
    })
}
