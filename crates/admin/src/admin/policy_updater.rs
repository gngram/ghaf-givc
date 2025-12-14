use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::lchown;
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
    repo_head: Option<gix::hash::ObjectId>,
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
            repo_head: None,
        };

        /* Attempt to load and validate policies from the existing repository */
        if updater.destination.exists() {
            match gix::open(&updater.destination) {
                Ok(repo) => {
                    /*
                      Validate branch and URL match from config.
                      Branch is fixed to avoid any merge conflict.
                    */
                    let head_ref = repo.head()?;
                    let _current_branch = head_ref
                        .referent_name()
                        .map(|r| r.shorten().to_string())
                        .unwrap_or_default();

                    let remote_url = repo
                        .config_snapshot()
                        .string("remote.origin.url")
                        .map(|s| s.to_string())
                        .unwrap_or_default();

                    if remote_url == updater.url {
                        info!(
                            "[POLICY] Successfully loaded existing repository from '{}'",
                            updater.destination.display()
                        );
                        let head = repo.head_id()?;
                        updater.repo_head = Some(head.detach());
                        updater.repo = Some(repo);
                        return Ok(updater);
                    } else {
                        info!(
                            "[POLICY] Repository at '{}' is not from provided source. Re-cloning...",
                            updater.destination.display()
                        );
                    }
                }
                Err(_) => {
                    info!(
                        "[POLICY] Path '{}' exists but is not a valid git repository. Re-cloning...",
                        updater.destination.display()
                    );
                }
            }
        }

        loop {
            match updater.clone_repo() {
                Ok(()) => break,
                Err(e) => {
                    error!("[POLICY] Clone failed: {}. Retrying in 5 mins...", e);
                    thread::sleep(Duration::from_secs(300));
                }
            }
        }
        Ok(updater)
    }

    fn clone_repo(&mut self) -> Result<()> {
        info!("[POLICY] Cloning repository from: {}", self.url);
        info!("[POLICY] Branch: {}", self.branch);
        info!("[POLICY] Destination: {:?}", self.destination);

        let temp_destination = self.destination.with_extension("tmp");

        if temp_destination.exists() {
            std::fs::remove_dir_all(&temp_destination).with_context(|| {
                format!(
                    "Failed to delete temporary directory '{}'",
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

        if self.destination.exists() {
            std::fs::remove_dir_all(&self.destination)
                .context("Failed to remove existing destination")?;
        }

        std::fs::rename(&temp_destination, &self.destination)
            .context("Failed to move temp repo to destination")?;

        let opa_dir = self.destination.join("opa");
        if opa_dir.exists() {
            let (uid, gid) = get_opa_ids()?;
            for entry in walkdir::WalkDir::new(&opa_dir) {
                let entry = entry?;
                lchown(entry.path(), Some(uid), Some(gid))
                    .with_context(|| format!("Failed to chown {:?}", entry.path()))?;
            }
        }

        let repo = gix::open(&self.destination)?;

        let head = repo.head_id()?;
        self.repo_head = Some(head.detach());
        self.repo = Some(repo);

        info!("[POLICY] Repository cloned successfully.");
        info!(
            "[POLICY] Checked out HEAD: {}",
            self.repo_head.as_ref().unwrap()
        );
        Ok(())
    }

    pub fn repo_head(&self) -> Option<gix::hash::ObjectId> {
        self.repo_head
    }

    fn fetch(&self) -> Result<()> {
        let repo = self.repo.as_ref().context("Repo should be initialized")?;
        let remote_name = self.remote_name.as_str();
        let remote = repo.find_remote(remote_name)?;

        let mut progress = gix::progress::Discard;
        let _fetch_outcome = remote
            .connect(gix::remote::Direction::Fetch)?
            .prepare_fetch(&mut progress, Default::default())?
            .receive(progress, &gix::interrupt::IS_INTERRUPTED)?;
        Ok(())
    }

    fn checkout(&mut self, commit_id: gix::hash::ObjectId) -> Result<()> {
        let repo = self.repo.as_ref().context("Repo should be initialized")?;
        let local_branch = format!("refs/heads/{}", self.branch);
        let remote_name = self.remote_name.as_str();

        // Create or update local branch
        match repo.find_reference(&local_branch) {
            Ok(mut branch_ref) => {
                // Branch exists, update it
                branch_ref.set_target_id(commit_id, "fast-forward from remote")?;
            }
            Err(_) => {
                // Create new branch
                repo.reference(
                    local_branch.as_str(),
                    commit_id,
                    gix::refs::transaction::PreviousValue::MustNotExist,
                    format!("branch from {}/{}", remote_name, self.branch),
                )?;
            }
        }

        // Update HEAD to point to the branch symbolically
        std::fs::write(
            repo.git_dir().join("HEAD"),
            format!("ref: {}\n", local_branch),
        )?;

        // Perform checkout to update working directory
        let commit = repo.find_object(commit_id)?.into_commit();
        let tree = commit.tree()?;

        // Checkout the tree to the working directory
        let mut index = repo.index_from_tree(&tree.id)?;
        let opts = gix::worktree::state::checkout::Options {
            overwrite_existing: true,
            ..Default::default()
        };
        let objects = repo.objects.clone().into_arc()?;

        gix::worktree::state::checkout(
            &mut index,
            repo.workdir()
                .context("[POLICY] Repository has no working directory")?,
            objects,
            &gix::progress::Discard,
            &gix::progress::Discard,
            &gix::interrupt::IS_INTERRUPTED,
            opts,
        )?;

        // Write the index to disk
        index.write(gix::index::write::Options::default())?;

        // Update repo_head to the new commit
        self.repo_head = Some(commit_id);
        info!("[POLICY] Checked out HEAD: {}", commit_id);
        Ok(())
    }

    pub fn get_update(&mut self) -> Result<Option<gix::hash::ObjectId>> {
        if self.repo.is_none() {
            info!("[POLICY] Repo not valid, cloning..");
            loop {
                match self.clone_repo() {
                    Ok(()) => break,
                    Err(e) => {
                        error!("[POLICY] Clone failed: {}. Retrying in 5 mins...", e);
                        thread::sleep(Duration::from_secs(300));
                    }
                }
            }
        }
        // Store the old head for comparison
        let old_head = self.repo_head;

        self.fetch()?;

        let commit_id = {
            let repo = self
                .repo
                .as_ref()
                .context("[POLICY] Repo should be initialized")?;
            let remote_tracking = format!("refs/remotes/{}/{}", self.remote_name, self.branch);
            let remote_ref = repo.find_reference(&remote_tracking)?;
            remote_ref.id().detach()
        };

        self.checkout(commit_id)?;

        // Return the new head if it changed, otherwise None
        if old_head != self.repo_head {
            Ok(old_head)
        } else {
            Ok(None)
        }
    }

    pub fn get_change_set(&self, from_rev: &str, to_rev: &str) -> Result<String> {
        let repo = self
            .repo
            .as_ref()
            .context("[POLICY] Repository not loaded. Call clone_repo or load_from_path first.")?;

        info!("[POLICY] Diffing {} -> {}", from_rev, to_rev);

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

fn get_updated_vms(changeset: &str) -> Vec<String> {
    let mut dirs = HashSet::new();

    for line in changeset.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Expect format like: "M  vm-policies/gui-vm/rules.json"
        // Split once on whitespace to drop the status part.
        let mut parts = line.split_whitespace();

        // First is status ("M", "A", etc.), second is the path
        let _status = parts.next();
        let path = match parts.next() {
            Some(p) => p,
            None => continue,
        };

        // We only care about paths that are within vm-policies/
        const PREFIX: &str = "vm-policies/";
        if !path.starts_with(PREFIX) {
            continue;
        }

        // Take the component immediately after "vm-policies/"
        // e.g. "vm-policies/gui-vm/rules.json" -> "gui-vm"
        let rest = &path[PREFIX.len()..];
        if let Some(first_component) = rest.split('/').next() {
            if !first_component.is_empty() {
                dirs.insert(first_component.to_string());
            }
        }
    }

    // Turn into sorted Vec if you want deterministic order
    let mut result: Vec<String> = dirs.into_iter().collect();
    result.sort();
    result
}

fn archive_policies_for_vm(vm_root: &Path, vm_name: &str, output_dir: &Path) -> anyhow::Result<()> {
    let vm_path = vm_root.join(vm_name);
    if !vm_path.exists() {
        anyhow::bail!(
            "[POLICY] VM directory does not exist: {}",
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

    // Iterate all files recursively inside vm-policies/<vmname>
    for entry in walkdir::WalkDir::new(&vm_path) {
        let entry = entry?;
        let path = entry.path();

        if path == vm_path {
            continue; // skip the root folder itself
        }

        let relative_path = path.strip_prefix(&vm_path)?;

        // Add the file to the tar with ONLY the relative path
        tar.append_path_with_name(path, relative_path)?;
    }

    tar.finish()?;
    println!("[POLICY] Created {}", out_file_path.display());
    Ok(())
}

fn ensure_policy_cache(
    vm_root: &Path,
    output_dir: &Path,
    head_file_path: &Path,
    new_head: &str,
) -> anyhow::Result<()> {
    if !vm_root.exists() {
        return Ok(());
    }

    let old_head = fs::read_to_string(head_file_path)
        .ok()
        .map(|s| s.trim().to_string());

    if let Some(old) = &old_head {
        if old == new_head {
            info!("[POLICY] Policy cache is up-to-date.");
            return Ok(());
        }
    }

    fs::remove_dir_all(output_dir)?;
    fs::create_dir_all(output_dir)?;

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

    let mut head_file = fs::File::create(head_file_path)?;
    head_file.write_all(new_head.as_bytes())?;
    info!("[POLICY] Policy cache updated");

    Ok(())
}

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

        if file_type.is_dir() {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|os| anyhow::anyhow!("Non-UTF8 VM directory name: {:?}", os))?;

            if name.ends_with(".tar.gz") {
                let vmname = name.trim_end_matches(".tar.gz");
                let _ =
                    push_vm_policy_updates(admin_service.clone(), &vmname, cache_dir, "", sha, "");
            }
        }
    }
    Ok(())
}

pub fn push_vm_policy_updates(
    admin_service: Arc<super::server::AdminServiceImpl>,
    vm_name: &str,
    cache_dir: &Path,
    old_rev: &str,
    new_rev: &str,
    change_set: &str,
) {
    let cache_dir = cache_dir.to_path_buf();

    info!("[POLICY] Preparing policy update push for {}", vm_name);

    let admin_service = admin_service.clone();
    let old = old_rev.to_string();
    let new = new_rev.to_string();
    let changes = change_set.to_string();
    let policy_archive = cache_dir.join(format!("{}.tar.gz", vm_name));
    let vm_name = vm_name.to_string();

    tokio::spawn(async move {
        if let Err(e) = admin_service
            .push_policy_update(&vm_name, &policy_archive, &old, &new, &changes)
            .await
        {
            error!(
                "[POLICY] Failed to push policy update to {}: {}",
                vm_name, e
            );
        } else {
            info!("[POLICY] Successfully pushed policy update for {}", vm_name);
        }
    });
}

pub async fn update_policies(
    admin_service: Arc<super::server::AdminServiceImpl>,
    policy_url: String,
    poll_interval: Duration,
    policyroot: &Path,
    branch: String,
) -> thread::JoinHandle<()> {
    let policyroot = policyroot.to_path_buf();
    info!("POLICY_AGENT---spawning...");
    thread::spawn(move || {
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
                error!("[POLICY] Failed to initialize RepoUpdater: {}", e);
                return;
            }
        };

        let head_str = updater
            .repo_head()
            .map(|h| h.to_string())
            .unwrap_or_else(|| "UNKNOWN".into());

        info!("[POLICY] Current HEAD is: {}", head_str);

        let _ = ensure_policy_cache(&vmpolicies, policycache, &shafile, &head_str);

        let wait_time = if poll_interval == Duration::ZERO {
            Duration::from_secs(300)
        } else {
            poll_interval
        };

        loop {
            info!("\n[POLICY] --- Checking for policy updates ---");
            match updater.get_update() {
                Ok(Some(old_head)) => {
                    let new_head = updater.repo_head().unwrap();
                    info!(
                        "[POLICY] Policy update found! Fetched changes from {} to {}",
                        old_head, new_head
                    );

                    match updater.get_change_set(&old_head.to_string(), &new_head.to_string()) {
                        Ok(changes) => {
                            if !changes.is_empty() {
                                debug!("[POLICY] Changeset:\n{}", changes);

                                let changed_vms = get_updated_vms(&changes);
                                debug!("[POLICY] Changed vm-policies subdirs: {:?}", changed_vms);

                                for vm in changed_vms {
                                    match archive_policies_for_vm(
                                        vmpolicies.as_path(),
                                        &vm,
                                        &policycache,
                                    ) {
                                        Ok(_) => {
                                            info!("[POLICY] Created tar for {}", vm);
                                            if let Err(e) = fs::File::create(&shafile)
                                                .and_then(|mut f| f.write_all(new_head.as_bytes()))
                                            {
                                                error!(
                                                    "[POLICY] Failed to write head to file: {}",
                                                    e
                                                );
                                            }
                                            push_vm_policy_updates(
                                                admin_service.clone(),
                                                &vm,
                                                policycache,
                                                &old_head.to_string(),
                                                &new_head.to_string(),
                                                &changes,
                                            );
                                            if poll_interval == Duration::ZERO {
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "[POLICY] Failed to create tar for {}: {}",
                                                vm, e
                                            );
                                        }
                                    }
                                }
                            } else {
                                info!(
                                    "[POLICY] Update applied, but no file changes were detected in the diff."
                                );
                            }
                        }
                        Err(e) => error!("[POLICY] Failed to compute change set: {}", e),
                    }
                }
                Ok(None) => info!("[POLICY] Repository is already up-to-date."),
                Err(e) => error!("[POLICY] An error occurred during pull: {}", e),
            }
            thread::sleep(wait_time);
        }
    })
}

fn get_opa_ids() -> Result<(u32, u32)> {
    let uid = get_id_from_file("/etc/passwd", "opa").context("User opa not found")?;
    let gid = get_id_from_file("/etc/group", "opa").context("Group opa not found")?;
    Ok((uid, gid))
}

fn get_id_from_file(path: &str, name: &str) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()?
        .lines()
        .find(|line| line.starts_with(name) && line.as_bytes().get(name.len()) == Some(&b':'))
        .and_then(|line| line.split(':').nth(2))
        .and_then(|s| s.parse().ok())
}
