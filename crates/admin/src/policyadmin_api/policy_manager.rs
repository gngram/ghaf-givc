use crate::admin::server;
use crate::policyadmin_api::policy_repo::PolicyRepository;
use crate::utils::json::JsonNode;
use anyhow::Result;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Arc;
use std::thread;
use tar::Builder;
use tokio::runtime::Runtime;
use tracing::{debug, error, info};

use crossbeam_channel::{Receiver, Sender, unbounded};
use std::collections::HashMap;
use std::thread::{self, JoinHandle};

/// The message format containing two strings
pub struct Policy {
    pub metadata: String,
    pub file: String,
}

pub struct PolicyManager {
    policy_dir: PathBuf,
    configs: JsonNode,
    admin_service: Arc<server::AdminServiceImpl>,
    rt: Arc<Runtime>,
    workers: HashMap<String, (Sender<Policy>, JoinHandle<()>)>,
}

impl PolicyManager {
    pub fn new(
        policy_path: &Path,
        config_path: &Path,
        admin_service: Arc<server::AdminServiceImpl>,
    ) -> Result<Self> {
        let configs = JsonNode::from_file(config_path)?;
        let rt = Runtime::new().map_err(|e| anyhow!("Failed to create Tokio runtime: {e}"))?;
        let rt = Arc::new(rt);

        let mut instance = Self {
            policy_path: policy_path.to_path_buf(),
            configs,
            admin_service,
            rt,
            workers: HashMap::new(),
        };

        let policies = configs.get_keys(&["policies"]);
        for policy in policies {
            let vms = configs.get_keys(&["policies", &policy, "vms"]);
            for vm in vms {
                instance.add_worker(&vm);
            }
        }

        Ok(instance)
    }

    pub fn add_worker(&mut self, vm: &str) {
        if self.workers.contains_key(vm) {
            return;
        }

        let (tx, rx) = unbounded::<Policy>();
        let vmname = vm.to_string();
        let vmname_for_thread = vmname.clone();
        let rt_share = Arc::clone(&self.rt);

        let handle = thread::spawn(move || {
            Self::worker_handler(vmname_for_thread, rx, rt_share);
        });

        self.workers.insert(vmname, (tx, handle));
    }

    pub fn worker_handler(vm: String, rx: Receiver<Policy>, rt: Arc<Runtime>) {
        println!("Worker [{}] started via member function.", vm);

        while let Ok(msg) = rx.recv() {
            println!(
                "Worker [{}] processing: {} & {}",
                vm, msg.metadata, msg.file
            );
            let mut metadata = JsonNode::new();

            let result = rt.block_on(async {
                admin_service
                    .push_policy_update(&vm_name, &msg.file, &msg.metadata)
                    .await
            });

            if let Err(e) = result {
                error!(
                    "policy-manager: Failed to push policy update to {}: {}",
                    vm_name, e
                );
            } else {
                info!(
                    "policy-manager: Successfully pushed policy update for {}",
                    vm_name
                );
            };
        }
        println!("Worker [{}] shutting down.", vm);
    }

    pub fn send_task(&self, vm: &str, a: String, b: String) -> Result<(), String> {
        if let Some((tx, _)) = self.workers.get(vm) {
            tx.send(Policy {
                metadata: a,
                file: b,
            })
            .map_err(|_| "Failed to send: Thread might have panicked".to_string())
        } else {
            Err("Worker not found".to_string())
        }
    }

    pub fn update_vm(&self, vm_name: &str) -> Result<()> {
        let policies = self.configs.get_keys(&["policies"]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        for policy in policies {
            if fs::metadata(&self.policy_path.join(&policy)).is_ok() {
                let vms = self.configs.get_keys(&["policies", &policy, "vms"]);
                /* if vm_name is in vms */
                if vms.contains(&vm_name) {
                    for entry in fs::read_dir(&self.policy_path.join(&policy))? {
                        let entry = entry?;
                        let path = entry.path();
                        let mut metadata = JsonNode::new();
                        metadata.add_field(&["file"], json!(entry.file_name().to_str()));
                        metadata.add_field(&["name"], json!(vm));
                        match metadata.to_string() {
                            Ok(metadata_str) => {
                                match self.send_task(vm_name, metadata_str, path.to_string()) {
                                    Ok(_) => {
                                        info!("Policy update sent successfully");
                                    }
                                    Err(e) => {
                                        error!("Failed to send policy update: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to serialize metadata: {}", e);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /* Force update all VMs policy */
    pub fn update_all_vms(&self) -> Result<()> {
        for (vm, _) in self.workers.iter() {
            self.update_vm(vm)?;
        }
        Ok(())
    }

    /* Sends policy update to vms  */
    fn update_changeset_to_vms(&self, changeset: &str) -> Result<()> {
        for line in changeset.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            /*
             * Expect git changeset line format like: "M  vm-policies/<policy-name>/<policy-file>".
             * Split once on whitespace to drop the status part.
             */
            let mut parts = line.split_whitespace();

            /* First is status ("M", "A", "D", etc.), second is the path */
            let _status = parts.next();
            let path = match parts.next() {
                Some(p) => p,
                None => continue,
            };

            /* Consider only lines with "vm-policies/" prefix */
            const PREFIX: &str = "vm-policies/";
            if !path.starts_with(PREFIX) {
                continue;
            }

            /* take the two components after "vm-policies/" to get the policy name and file name */
            let rest = &path[PREFIX.len()..];
            if let Some(policy_name) = rest.split('/').next() {
                /* Get second component */
                if let Some(file_name) = rest.split('/').nth(1) {
                    let file_path = self.policy_path.join(policy_name).join(file_name);
                    if fs::metadata(&file_path).is_ok() {
                        let vms = self.configs.get_keys(&["policies", &policy_name, "vms"]);
                        for vm in vms {
                            match self.send_task(vm, policy_name.to_string(), file_path.to_string())
                            {
                                Ok(_) => {
                                    info!("Policy update sent successfully");
                                }
                                Err(e) => {
                                    error!("Failed to send policy update: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
