use crate::admin::server;
use crate::policyadmin_api::policy_repo::PolicyRepository;
use anyhow::Result;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use tar::Builder;
use tracing::{debug, error, info};

use crate::utils::json::JsonNode;

/* PolicyManager structure - manages policy updates and distribution */
pub struct PolicyManager {
    vm_policies_path: PathBuf,
    policy_cache_path: PathBuf,
    sha_file_path: PathBuf,
    admin_service: Arc<server::AdminServiceImpl>,
}

impl PolicyManager {
    pub fn new(policy_root: &Path, admin_service: Arc<server::AdminServiceImpl>) -> Result<Self> {
        let policy_dir = policy_root.join("data");
        let vm_policies_path = policy_dir.join("vm-policies");
        let policy_cache_path = policy_root.join(".cache");
        let sha_file_path = policy_cache_path.join(".rev");

        Ok(Self {
            vm_policies_path,
            policy_cache_path,
            sha_file_path,
            admin_service,
        })
    }

    /* Returns vector of VMs which have been modified in policy update */
    fn get_updated_vms(&self, changeset: &str) -> Vec<String> {
        let mut dirs = HashSet::new();

        for line in changeset.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            /*
             * Expect git changeset line format like: "M  vm-policies/gui-vm/rules.json".
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

            /*
             * Take the component immediately after "vm-policies/" to get the VM name.
             * e.g. "vm-policies/gui-vm/rules.json" -> "gui-vm"
             */
            let rest = &path[PREFIX.len()..];
            if let Some(first_component) = rest.split('/').next() {
                if !first_component.is_empty() {
                    dirs.insert(first_component.to_string());
                }
            }
        }

        /* Sort and return the result */
        let mut result: Vec<String> = dirs.into_iter().collect();
        result.sort();
        result
    }

    /* Create a tar.gz archive of the VM policies and store in output_dir */
    fn archive_policies_for_vm(&self, vm_name: &str) -> Result<()> {
        let vm_path = self.vm_policies_path.join(vm_name);
        if !vm_path.exists() {
            anyhow::bail!(
                "policy-manager: VM directory does not exist: {}",
                vm_path.display()
            );
        }

        /* Return if vm_root doesn't exist */
        if !self.vm_policies_path.exists() {
            return Ok(());
        }

        let out_file_path = self.policy_cache_path.join(format!("{}.tar.gz", vm_name));
        let tar_gz = fs::File::create(&out_file_path)?;
        let enc = GzEncoder::new(tar_gz, Compression::default());
        let mut tar = Builder::new(enc);

        /* Iterate all files recursively inside vm-policies/<vmname> */
        for entry in walkdir::WalkDir::new(&vm_path) {
            let entry = entry?;
            let path = entry.path();

            /* Skip the root folder itself */
            if path == vm_path {
                continue;
            }

            let relative_path = path.strip_prefix(&vm_path)?;

            /* Add the file to the tar with ONLY the relative path */
            tar.append_path_with_name(path, relative_path)?;
        }

        tar.finish()?;
        println!("policy-manager: Created {}", out_file_path.display());
        Ok(())
    }

    /* Ensures that policy cache is up-to-date */
    pub fn ensure_policy_cache(&self, new_head: &str) -> Result<bool> {
        if !self.vm_policies_path.exists() {
            return Ok(false);
        }

        /* If policy cache head is up-to-date return early */
        let old_head = fs::read_to_string(&self.sha_file_path)
            .ok()
            .map(|s| s.trim().to_string());

        if let Some(old) = &old_head {
            if old == new_head {
                info!("policy-manager: Policy cache is up-to-date.");
                return Ok(false);
            }
        }

        if self.policy_cache_path.exists() {
            fs::remove_dir_all(&self.policy_cache_path)?;
        }
        fs::create_dir_all(&self.policy_cache_path)?;

        /* Archive each VM policy and store in cache */
        for entry in fs::read_dir(&self.vm_policies_path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;

            if file_type.is_dir() {
                let vm_name = entry
                    .file_name()
                    .into_string()
                    .map_err(|os| anyhow::anyhow!("Non-UTF8 VM directory name: {:?}", os))?;

                self.archive_policies_for_vm(&vm_name)?;
            }
        }

        /* Update policy cache head */
        let mut head_file = fs::File::create(&self.sha_file_path)?;
        head_file.write_all(new_head.as_bytes())?;
        info!("policy-manager: Policy cache updated");

        Ok(true)
    }

    /* Force update all VMs policy */
    pub fn update_all_vms(&self, sha: &str) -> Result<()> {
        if !self.policy_cache_path.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.policy_cache_path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;

            if !file_type.is_dir() {
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|os| anyhow::anyhow!("Non-UTF8 VM directory name: {:?}", os))?;

                if name.ends_with(".tar.gz") {
                    let vmname = name.trim_end_matches(".tar.gz");
                    self.push_vm_policy_updates(vmname, "", sha, "");
                    info!("policy-manager: Policy pushed to VM {}", name);
                }
            }
        }

        Ok(())
    }

    /* Pushes policy update to VM policyAdmin */
    pub fn push_vm_policy_updates(
        &self,
        vm_name: &str,
        old_rev: &str,
        new_rev: &str,
        change_set: &str,
    ) {
        info!(
            "policy-manager: Preparing policy update push for {}",
            vm_name
        );

        let admin_service = self.admin_service.clone();
        let old = old_rev.to_string();
        let new = new_rev.to_string();
        let changes = change_set.to_string();
        let policy_archive = self.policy_cache_path.join(format!("{}.tar.gz", vm_name));
        let vm_name = vm_name.to_string();

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut metadata = JsonNode::new();
            metadata.add_field(&["type"], json!("repo"));
            metadata.add_field(&["rev"], json!(new));
            metadata.add_field(&["base"], json!(old));
            metadata.add_field(&["changeset"], json!(changes));
            match metadata.to_string() {
                Ok(metadata_str) => {
                    let result = rt.block_on(async {
                        admin_service
                            .push_policy_update(&vm_name, &policy_archive, &metadata_str)
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
                Err(e) => {
                    error!(
                        "policy-manager: Failed to push policy update to {}: {}",
                        vm_name, e
                    );
                }
            }
        });
    }

    /* Process policy update - archive changed VMs and push updates */
    pub fn process_policy_update(
        &self,
        updater: &mut PolicyRepository,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

        let changes = updater.get_change_set(&old_head.to_string(), &new_head.to_string())?;

        if !changes.is_empty() {
            debug!("policy-manager: Changeset:\n{}", changes);
            let changed_vms = self.get_updated_vms(&changes);
            debug!(
                "policy-manager: Changed vm-policies subdirs: {:?}",
                changed_vms
            );

            for vm in changed_vms {
                self.archive_policies_for_vm(&vm)?;
                info!("policy-manager: Created tar for {}", vm);

                fs::File::create(&self.sha_file_path)
                    .and_then(|mut f| f.write_all(new_head.as_bytes()))?;

                self.push_vm_policy_updates(
                    &vm,
                    &old_head.to_string(),
                    &new_head.to_string(),
                    &changes,
                );
            }
        } else {
            info!("policy-manager: Update applied, but no VM was modified.");
        }

        Ok(())
    }
}
