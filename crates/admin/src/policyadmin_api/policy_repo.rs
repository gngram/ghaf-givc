use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, error, info};

use gix;
use gix::bstr::ByteSlice;
use gix::object::tree::diff::{Action, Change};

/* PolicyRepository structure */
pub struct PolicyRepository {
    pub url: String,
    pub branch: String,
    pub destination: PathBuf,
    pub remote_name: String,

    repo: Option<gix::Repository>,
    new_head: Option<gix::hash::ObjectId>,
    old_head: Option<gix::hash::ObjectId>,
}

impl PolicyRepository {
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
        let mut policy = Self {
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
        if policy.destination.exists() {
            match gix::open(&policy.destination) {
                Ok(repo) => {
                    let remote_url = repo
                        .config_snapshot()
                        .string("remote.origin.url")
                        .map(|s| s.to_string())
                        .unwrap_or_default();

                    if remote_url == policy.url {
                        let head = repo.head_id()?;
                        policy.new_head = Some(head.detach());
                        policy.old_head = Some(head.detach());
                        policy.repo = Some(repo);
                        return Ok(policy);
                    } else {
                        info!("policy-repo: updating default repository from remote");
                    }
                }
                Err(_) => {
                    info!("policy-repo: Not able to load policy repository Re-cloning...");
                }
            }
        }

        policy.ensure_clone();
        Ok(policy)
    }

    /* Clone the repository from the provided URL and ref */
    fn clone_repo(&mut self) -> Result<()> {
        info!("policy-repo: Cloning repository from: {}", self.url);
        info!("policy-repo: Branch: {}", self.branch);
        info!("policy-repo: Destination: {:?}", self.destination);

        /* Clone repository in a temporary directory */
        let temp_destination = self.destination.with_extension("tmp");

        if temp_destination.exists() {
            std::fs::remove_dir_all(&temp_destination).with_context(|| {
                format!(
                    "policy-repo: Failed to delete temporary directory '{}'",
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
                .context("policy-repo: Failed to remove existing destination")?;
        }

        std::fs::rename(&temp_destination, &self.destination)
            .context("policy-repo: Failed to move temp repo to destination")?;

        /* Reload the context from updated policies */
        let repo = gix::open(&self.destination)?;
        let head = repo.head_id()?;
        self.new_head = Some(head.detach());
        self.old_head = None;
        self.repo = Some(repo);

        info!(
            "policy-repo: Repository cloned successfully. HEAD: {}",
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
            .context("policy-repo: Repo should be initialized")?;

        let remote_name = self.remote_name.as_str();
        let remote = repo
            .find_remote(remote_name)
            .with_context(|| format!("policy-repo:Failed to find remote '{}'", remote_name))?;

        debug!("policy-repo: Fetching from remote: {}", remote_name);

        let mut progress = gix::progress::Discard;

        let connection = remote
            .connect(gix::remote::Direction::Fetch)
            .context("policy-repo:Failed to connect to remote")?;

        let prepare = connection
            .prepare_fetch(&mut progress, Default::default())
            .context("policy-repo:Failed to prepare fetch")?;

        let outcome = prepare
            .receive(&mut progress, &gix::interrupt::IS_INTERRUPTED)
            .context("policy-repo:Failed to receive objects from remote")?;

        debug!(
            "policy-repo: Fetch outcome: {} refs updated",
            outcome.ref_map.mappings.len()
        );

        Ok(())
    }

    /* Checkout the change set from the remote repository */
    fn checkout(&mut self, commit_id: gix::hash::ObjectId) -> Result<()> {
        let repo = self
            .repo
            .as_ref()
            .context("policy-repo: repo should be initialized")?;
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
                .context("policy-repo: Repository has no working directory")?,
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
        debug!("policy-repo: Checked out HEAD: {}", commit_id);
        Ok(())
    }

    pub fn ensure_clone(&mut self) -> Result<()> {
        loop {
            match self.clone_repo() {
                Ok(()) => {
                    info!("policy-repo: Repository cloned successfully.");
                    break;
                }
                Err(e) => {
                    error!("policy-repo: Clone failed: {}. Retrying in 5 mins...", e);
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
                .context("policy-repo: Repo should be initialized")?;
            let remote_tracking = format!("refs/remotes/{}/{}", self.remote_name, self.branch);
            let remote_ref = repo.find_reference(&remote_tracking)?;
            remote_ref.id().detach()
        };
        self.checkout(commit_id)?;
        if self.old_head != self.new_head {
            info!(
                "policy-repo: updated to commit {}",
                self.new_head.as_ref().unwrap()
            );
            Ok(true)
        } else {
            info!("policy-repo: policy is up-to-date");
            Ok(false)
        }
    }

    /* Returns changeset between two commits */
    pub fn get_change_set(&self, from_rev: &str, to_rev: &str) -> Result<String> {
        let repo = self
            .repo
            .as_ref()
            .context("policy-repo: Repo not initialized")?;
        info!("policy-repo: Diffing {} -> {}", from_rev, to_rev);

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
