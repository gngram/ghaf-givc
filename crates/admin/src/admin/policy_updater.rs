use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use flate2::Compression;
use flate2::write::GzEncoder;
use tar::Builder;
use tracing::{debug, error, info};

use gix;
use gix::bstr::ByteSlice;
use gix::object::tree::diff::{Action, Change};

/* RepoUpdater structure */
pub struct RepoUpdater {
    pub url: String,
    pub branch: String,
    pub destination: PathBuf,
    pub remote_name: String,

    repo: Option<gix::Repository>,
    new_head: Option<gix::hash::ObjectId>,
    old_head: Option<gix::hash::ObjectId>,
}

impl RepoUpdater {
    pub fn new<U: Into<String>, B: Into<String>, P: Into<PathBuf>>(
        url: U,
        branch: B,
        destination: P,
    ) -> Result<Self> {
        Self::new_inner(url, branch, destination, "origin")
    }

    fn new_inner<U: Into<String>, B: Into<String>, P: Into<PathBuf>, R: Into<String>>(
        url: U,
        branch: B,
        destination: P,
        remote: R,
    ) -> Result<Self> {
        let mut updater = Self {
            url: url.into(),
            branch: branch.into(),
            destination: destination.into(),
            remote_name: remote.into(),
            repo: None,
            new_head: None,
            old_head: None,
        };

        /*
         * Attempt to load and validate policies from the existing repository.
         * Default policy will not have remote information.
         * Once it will be cloned from the provided URL.
         */
        if updater.destination.exists() {
            match gix::open(&updater.destination) {
                Ok(repo) => {
                    let remote_url = repo
                        .config_snapshot()
                        .string("remote.origin.url")
                        .map(|s| s.to_string())
                        .unwrap_or_default();

                    if remote_url == updater.url {
                        let head = repo.head_id()?;
                        updater.new_head = Some(head.detach());
                        updater.old_head = Some(head.detach());
                        updater.repo = Some(repo);
                        updater.ensure_remote_configured()?;
                        info!(
                            "policy-updater: Successfully loaded existing repository from '{}' Current head is: '{}'",
                            updater.destination.display(),
                            updater.new_head.as_ref().unwrap()
                        );
                        return Ok(updater);
                    } else {
                        info!(
                            "policy-updater: Updating default repository '{}' from remote '{}'",
                            updater.destination.display(),
                            updater.url
                        );
                    }
                }
                Err(_) => {
                    info!(
                        "policy-updater: Path '{}' exists but is not a valid git repository. Re-cloning...",
                        updater.destination.display()
                    );
                }
            }
        }

        updater.ensure_clone();
        Ok(updater)
    }

    fn ensure_remote_configured(&self) -> Result<()> {
        let repo = self
            .repo
            .as_ref()
            .context("policy-updater: Repo should be initialized")?;

        let r = repo.find_remote(&*self.remote_name).with_context(|| {
            format!(
                "policy-updater: Remote '{}' not found in repository at {}. \
                 The repository may have been cloned incorrectly or the remote was removed.",
                self.remote_name,
                self.destination.display()
            )
        })?;
        info!(
            "policy-updater: Remote '{}' configured successfully: {:?}",
            self.remote_name, r
        );

        Ok(())
    }

    /* Clone the repository from the provided URL and ref */
    fn clone_repo(&mut self) -> Result<()> {
        info!("policy-updater: Cloning repository from: {}", self.url);
        info!("policy-updater: Branch: {}", self.branch);
        info!("policy-updater: Destination: {:?}", self.destination);

        /* Clone repository in a temporary directory */
        let temp_destination = self.destination.with_extension("tmp");

        if temp_destination.exists() {
            std::fs::remove_dir_all(&temp_destination).with_context(|| {
                format!(
                    "policy-updater: Failed to delete temporary directory '{}'",
                    temp_destination.display()
                )
            })?;
        }

        let interrupt = &gix::interrupt::IS_INTERRUPTED;

        let mut prepare = gix::prepare_clone(self.url.as_str(), &temp_destination)?
            .with_ref_name(Some(self.branch.as_str()))?;

        let (mut checkout, _fetch_outcome) =
            prepare.fetch_then_checkout(gix::progress::Discard, interrupt)?;

        let (repo, _checkout_outcome) =
            checkout.main_worktree(gix::progress::Discard, interrupt)?;

        drop(repo);

        /* Replace policy store with the new one */
        if self.destination.exists() {
            std::fs::remove_dir_all(&self.destination)
                .context("policy-updater: Failed to remove existing destination")?;
        }

        std::fs::rename(&temp_destination, &self.destination)
            .context("policy-updater: Failed to move temp repo to destination")?;

        /* Reload the context from updated policies */
        let repo = gix::open(&self.destination)?;
        let head = repo.head_id()?;
        self.new_head = Some(head.detach());
        self.old_head = None;
        self.repo = Some(repo);
        self.ensure_remote_configured()?;

        info!(
            "policy-updater: Repository cloned successfully. HEAD: {}",
            self.new_head.as_ref().unwrap()
        );
        Ok(())
    }

    /* Returns policy repo HEAD */
    pub fn current_head(&self) -> Option<gix::hash::ObjectId> {
        self.new_head
    }

    /* Returns policy repo HEAD */
    pub fn old_head(&self) -> Option<gix::hash::ObjectId> {
        self.old_head
    }

    /* Fetches the latest changes from the remote repository */

    fn fetch(&self) -> Result<()> {
        let repo = self
            .repo
            .as_ref()
            .context("policy-updater: Repo should be initialized")?;

        let remote_name = self.remote_name.as_str();
        let remote = repo
            .find_remote(remote_name)
            .with_context(|| format!("policy-updater:Failed to find remote '{}'", remote_name))?;

        debug!("policy-updater: Fetching from remote: {}", remote_name);

        let mut progress = gix::progress::Discard;

        let connection = remote
            .connect(gix::remote::Direction::Fetch)
            .context("policy-updater:Failed to connect to remote")?;

        let prepare = connection
            .prepare_fetch(&mut progress, Default::default())
            .context("policy-updater:Failed to prepare fetch")?;

        let outcome = prepare
            .receive(&mut progress, &gix::interrupt::IS_INTERRUPTED)
            .context("policy-updater:Failed to receive objects from remote")?;

        debug!(
            "policy-updater: Fetch outcome: {} refs updated",
            outcome.ref_map.mappings.len()
        );

        Ok(())
    }

    /* Checkout the change set from the remote repository */
    fn checkout(&mut self, commit_id: gix::hash::ObjectId) -> Result<()> {
        let repo = self
            .repo
            .as_ref()
            .context("policy-updater: Repo should be initialized")?;
        let local_branch = format!("refs/heads/{}", self.branch);
        let remote_name = self.remote_name.as_str();

        /* Create or update local branch */
        match repo.find_reference(&local_branch) {
            Ok(mut branch_ref) => {
                /* Branch exists, update it */
                branch_ref.set_target_id(commit_id, "fast-forward from remote")?;
            }
            Err(_) => {
                /* Create new branch */
                repo.reference(
                    local_branch.as_str(),
                    commit_id,
                    gix::refs::transaction::PreviousValue::MustNotExist,
                    format!("branch from {}/{}", remote_name, self.branch),
                )?;
            }
        }

        /* Update HEAD for remote tracking */
        std::fs::write(
            repo.git_dir().join("HEAD"),
            format!("ref: {}\n", local_branch),
        )?;

        /* Find the commit tree */
        let commit = repo.find_object(commit_id)?.into_commit();
        let tree = commit.tree()?;

        /* Checkout the commit tree to the working directory */
        let mut index = repo.index_from_tree(&tree.id)?;
        let opts = gix::worktree::state::checkout::Options {
            overwrite_existing: true,
            ..Default::default()
        };
        let objects = repo.objects.clone().into_arc()?;

        gix::worktree::state::checkout(
            &mut index,
            repo.workdir()
                .context("policy-updater: Repository has no working directory")?,
            objects,
            &gix::progress::Discard,
            &gix::progress::Discard,
            &gix::interrupt::IS_INTERRUPTED,
            opts,
        )?;

        /* Write the index to disk */
        index.write(gix::index::write::Options::default())?;

        /* Update new_head context to the new commit */
        self.old_head = self.new_head;
        self.new_head = Some(commit_id);
        debug!("policy-updater: Checked out HEAD: {}", commit_id);
        Ok(())
    }

    pub fn ensure_clone(&mut self) -> Result<()> {
        loop {
            match self.clone_repo() {
                Ok(()) => {
                    info!("policy-updater: Repository cloned successfully.");
                    break;
                }
                Err(e) => {
                    error!("policy-updater: Clone failed: {}. Retrying in 5 mins...", e);
                    thread::sleep(Duration::from_secs(300));
                }
            }
        }
        Ok(())
    }

    /* Fetches and checks out the latest changes from the remote repository */
    pub fn get_update(&mut self) -> Result<bool> {
        self.fetch()?;

        let commit_id = {
            let repo = self
                .repo
                .as_ref()
                .context("policy-updater: Repo should be initialized")?;
            let remote_tracking = format!("refs/remotes/{}/{}", self.remote_name, self.branch);
            let remote_ref = repo.find_reference(&remote_tracking)?;
            remote_ref.id().detach()
        };
        self.checkout(commit_id)?;
        if self.old_head != self.new_head {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /* Returns changeset between two commits */
    pub fn get_change_set(&self, from_rev: &str, to_rev: &str) -> Result<String> {
        let repo = self.repo.as_ref()?;
        info!("policy-updater: Diffing {} -> {}", from_rev, to_rev);

        let from_tree = repo.rev_parse_single(from_rev)?.object()?.peel_to_tree()?;
        let to_tree = repo.rev_parse_single(to_rev)?.object()?.peel_to_tree()?;
        let mut changes_str = String::new();

        from_tree
            .changes()?
            .for_each_to_obtain_tree(&to_tree, |change| {
                let line = match change {
                    Change::Modification { location, .. } => {
                        format!("M  {}\n", location.to_str_lossy())
                    }
                    Change::Addition { location, .. } => {
                        format!("A  {}\n", location.to_str_lossy())
                    }
                    Change::Deletion { location, .. } => {
                        format!("D  {}\n", location.to_str_lossy())
                    }
                    _ => String::new(),
                };
                changes_str.push_str(&line);

                Ok::<_, std::convert::Infallible>(Action::Continue)
            })?;

        Ok(changes_str)
    }
}

/* Returns vector of vms, which have been modified in policy update */
fn get_updated_vms(changeset: &str) -> Vec<String> {
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
fn archive_policies_for_vm(vm_root: &Path, vm_name: &str, output_dir: &Path) -> anyhow::Result<()> {
    let vm_path = vm_root.join(vm_name);
    if !vm_path.exists() {
        anyhow::bail!(
            "policy-updater: VM directory does not exist: {}",
            vm_path.display()
        );
    }
    /* Return if vm_root doesn't exists */
    if !vm_root.exists() {
        return Ok(());
    }

    let out_file_path = output_dir.join(format!("{}.tar.gz", vm_name));
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
    println!("policy-updater: Created {}", out_file_path.display());
    Ok(())
}

/* Ensures that policy cache is up-to-date */
fn ensure_policy_cache(
    vm_root: &Path,
    output_dir: &Path,
    head_file_path: &Path,
    new_head: &str,
) -> anyhow::Result<bool> {
    if !vm_root.exists() {
        return Ok(false);
    }

    /* If policy cache head is uptodate return early */
    let old_head = fs::read_to_string(head_file_path)
        .ok()
        .map(|s| s.trim().to_string());
    if let Some(old) = &old_head {
        if old == new_head {
            info!("policy-updater: Policy cache is up-to-date.");
            return Ok(false);
        }
    }

    fs::remove_dir_all(output_dir)?;
    fs::create_dir_all(output_dir)?;

    /* Archive each vm policy and store in cache */
    for entry in fs::read_dir(vm_root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            let vm_name = entry
                .file_name()
                .into_string()
                .map_err(|os| anyhow::anyhow!("Non-UTF8 VM directory name: {:?}", os))?;

            archive_policies_for_vm(vm_root, &vm_name, output_dir)?;
        }
    }

    /* Update policy cache head */
    let mut head_file = fs::File::create(head_file_path)?;
    head_file.write_all(new_head.as_bytes())?;
    info!("policy-updater: Policy cache updated");

    Ok(true)
}

/* Force update all VMs policy */
#[allow(unused)]
fn update_vms(
    admin_service: Arc<super::server::AdminServiceImpl>,
    cache_dir: &Path,
    sha: &str,
) -> anyhow::Result<()> {
    if !cache_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(cache_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;

        if !file_type.is_dir() {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|os| anyhow::anyhow!("Non-UTF8 VM directory name: {:?}", os))?;

            if name.ends_with(".tar.gz") {
                let vmname = name.trim_end_matches(".tar.gz");
                let _ =
                    push_vm_policy_updates(admin_service.clone(), &vmname, cache_dir, "", sha, "");
                info!("policy-updater: Policy pushed to VM {}", name);
            }
        }
    }

    Ok(())
}

/* Pushes policy update to VM policyAgent */
pub fn push_vm_policy_updates(
    admin_service: Arc<super::server::AdminServiceImpl>,
    vm_name: &str,
    cache_dir: &Path,
    old_rev: &str,
    new_rev: &str,
    change_set: &str,
) {
    let cache_dir = cache_dir.to_path_buf();

    info!(
        "policy-updater: Preparing policy update push for {}",
        vm_name
    );

    let admin_service = admin_service.clone();
    let old = old_rev.to_string();
    let new = new_rev.to_string();
    let changes = change_set.to_string();
    let policy_archive = cache_dir.join(format!("{}.tar.gz", vm_name));
    let vm_name = vm_name.to_string();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(async {
            admin_service
                .push_policy_update(&vm_name, &policy_archive, &old, &new, &changes)
                .await
        });

        if let Err(e) = result {
            error!(
                "policy-updater: Failed to push policy update to {}: {}",
                vm_name, e
            );
        } else {
            info!(
                "policy-updater: Successfully pushed policy update for {}",
                vm_name
            );
        }
    });
}

fn process_policy_update(
    updater: &mut RepoUpdater,
    vmpolicies: &Path,
    policycache: &Path,
    shafile: &Path,
    admin_service: Arc<super::server::AdminServiceImpl>,
) -> Result<(), Box<dyn std::error::Error>> {
    let new_head = updater
        .current_head()
        .ok_or("policy-updater: Failed to get current head.")?;
    let old_head = updater
        .old_head()
        .ok_or("policy-updater: Failed to get old head.")?;

    info!(
        "policy-updater: Policy update found! Fetched changes from {} to {}",
        old_head, new_head
    );

    let changes = updater.get_change_set(&old_head.to_string(), &new_head.to_string())?;

    if !changes.is_empty() {
        debug!("policy-updater: Changeset:\n{}", changes);
        let changed_vms = get_updated_vms(&changes);
        debug!(
            "policy-updater: Changed vm-policies subdirs: {:?}",
            changed_vms
        );

        for vm in changed_vms {
            archive_policies_for_vm(vmpolicies, &vm, policycache)?;
            info!("policy-updater: Created tar for {}", vm);

            fs::File::create(shafile).and_then(|mut f| f.write_all(new_head.as_bytes()))?;

            push_vm_policy_updates(
                admin_service.clone(),
                &vm,
                policycache,
                &old_head.to_string(),
                &new_head.to_string(),
                &changes,
            );
        }
    } else {
        info!("policy-updater: Update applied, but no VM was modified.");
    }

    Ok(())
}

pub async fn update_policies(
    admin_service: Arc<super::server::AdminServiceImpl>,
    policy_url: String,
    poll_interval: Duration,
    policyroot: &Path,
    branch: String,
) -> thread::JoinHandle<()> {
    let policyroot = policyroot.to_path_buf();
    info!("policy-updater: Starting policy updater...");
    thread::spawn(move || {
        info!("policy-updater: Thread spawned successfully");
        let prbinding = policyroot.join("data");
        let policydir = prbinding.as_path();
        let vmpolicies = policydir.join("vm-policies");
        let pcbinding = policyroot.join(".cache");
        let policycache = pcbinding.as_path();
        let shafile = policycache.join(".rev");
        let admin_service = admin_service.clone();

        let mut updater = match RepoUpdater::new(policy_url, branch, policydir) {
            Ok(u) => u,
            Err(e) => {
                error!("policy-updater: Failed to initialize RepoUpdater: {}", e);
                return;
            }
        };

        let head_str = updater
            .current_head()
            .map(|h| h.to_string())
            .unwrap_or_else(|| "UNKNOWN".into());

        info!("policy-updater: Current HEAD is: {}", head_str);

        match ensure_policy_cache(&vmpolicies, policycache, &shafile, &head_str) {
            Ok(updated) => {
                if updated {
                    update_vms(admin_service.clone(), policycache, &head_str);
                } else {
                    info!("policy-updater: Policy cache is up-to-date.");
                }
            }
            Err(e) => {
                error!("policy-updater: Policy cache update failed: {}", e);
            }
        }

        let wait_time = if poll_interval == Duration::ZERO {
            Duration::from_secs(30)
        } else {
            poll_interval
        };
        let mut update_err = false;

        loop {
            info!("policy-updater: --- Checking for policy updates ---");
            match updater.get_update() {
                Ok(true) => {
                    match process_policy_update(
                        &mut updater,
                        &vmpolicies,
                        policycache,
                        &shafile,
                        admin_service.clone(),
                    ) {
                        Ok(()) => {
                            if poll_interval == Duration::ZERO {
                                return;
                            }
                        }
                        Err(e) => {
                            error!("policy-updater: Policy update processing failed: {}", e);
                            update_err = true;
                        }
                    }
                }
                Ok(false) => info!("policy-updater: Repository is already up-to-date."),
                Err(e) => {
                    error!(
                        "policy-updater: An error occurred during get_update(): {}",
                        e
                    );
                    update_err = true;
                }
            }
            if update_err {
                updater.ensure_clone();
                let new_head = updater
                    .current_head()
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "UNKNOWN".into());
                match ensure_policy_cache(&vmpolicies, policycache, &shafile, &new_head) {
                    Ok(updated) => {
                        if updated {
                            update_vms(admin_service.clone(), policycache, &new_head);
                        } else {
                            info!("policy-updater: Policy cache is up-to-date.");
                        }
                    }
                    Err(e) => {
                        error!("policy-updater: Policy cache update failed: {}", e);
                    }
                }
                update_err = false;
            }
            thread::sleep(wait_time);
        }
    })
}
