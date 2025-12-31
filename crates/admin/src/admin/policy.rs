use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info};

use crate::policyadmin_api::policy_manager::PolicyManager;
use crate::policyadmin_api::policy_repo::PolicyRepository;

pub async fn start_policy_monitor(
    admin_service: Arc<super::server::AdminServiceImpl>,
    policy_url: String,
    poll_interval: Duration,
    policyroot: &Path,
    branch: String,
) -> thread::JoinHandle<()> {
    let policyroot = policyroot.to_path_buf();
    info!("policy-monitor: starting policy monitor...");

    thread::spawn(move || {
        info!("policy-monitor: thread spawned successfully");

        let policy_manager = match PolicyManager::new(&policyroot, admin_service.clone()) {
            Ok(pm) => pm,
            Err(e) => {
                error!("policy-monitor: failed to initialize policy manager: {}", e);
                return;
            }
        };

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
                    if let Err(e) = policy_manager.process_policy_update(&mut policy_repo) {
                        error!("policy-monitor: policy update processing failed: {}", e);
                        update_err = true;
                    } else {
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

                match policy_manager.ensure_policy_cache(&new_head) {
                    Ok(updated) => {
                        if updated {
                            info!("policy-monitor: policy cache updated to {}", new_head);
                            let _ = policy_manager.update_all_vms(&new_head);
                        } else {
                            info!("policy-monitor: policy cache is up-to-date.");
                        }
                    }
                    Err(e) => {
                        error!("policy-monitor: policy cache update failed: {}", e);
                    }
                }
                update_err = false;
            }

            thread::sleep(wait_time);
        }
    })
}
