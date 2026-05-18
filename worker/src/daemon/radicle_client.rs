//! Radicle client — workspace provisioning for the escrow relayer.
//!
//! Wraps the vendored `radicle` crate (heartwood 1.8.0) to provide:
//! - Repo creation (rad init)
//! - Profile loading
//! - Repo cloning (fetch + fork + checkout)
//! - Patch listing
//! - Directory hashing (verify_hash)
//!
//! All operations are synchronous — the radicle crate uses blocking I/O
//! over Unix sockets and git2.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use sha2::Digest;
use tracing::{info, warn};

// ── Radicle imports ────────────────────────────────────────────────────
use radicle::cob::ObjectId;
use radicle::cob::patch::cache::Patches as PatchesTrait;
use radicle::identity::project::ProjectName;
use radicle::node::{Handle, Node};
use radicle::prelude::*;
use radicle::profile::Profile;

// ── Public types ───────────────────────────────────────────────────────

/// Workspace info produced after provisioning a task repo.
#[derive(Debug, Clone)]
pub struct WorkspaceInfo {
    /// Radicle repo ID (e.g. `rad:z3gqcJUoA1N9ydUDWw2BDgKmBgSJo`).
    pub rid: String,
    /// Local path where the repo was initialized.
    pub path: PathBuf,
}

/// Input file to write into the repo's `input/` directory.
#[derive(Debug, Clone)]
pub struct InputFile {
    /// Relative path within input/ (e.g. "dataset.csv", "src/main.py").
    pub path: String,
    /// File contents.
    pub content: Vec<u8>,
}

/// Summary of a Radicle patch.
#[derive(Debug, Clone)]
pub struct PatchSummary {
    pub id: String,
    pub title: String,
    pub state: String,
    pub head: String,
    pub base: String,
}

// ── RadicleClient ─────────────────────────────────────────────────────

/// Client wrapping a Radicle profile + node connection.
pub struct RadicleClient {
    profile: Profile,
    work_dir: PathBuf,
}

impl RadicleClient {
    /// Load the Radicle profile from `~/.radicle` (or `RAD_HOME`).
    ///
    /// Requires an initialized Radicle node (`rad auth` has been run).
    /// `work_dir` is the parent directory where task repos are created.
    pub fn new(work_dir: impl AsRef<Path>) -> Result<Self> {
        let work_dir = work_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&work_dir)
            .with_context(|| format!("creating work_dir: {}", work_dir.display()))?;

        let profile = Profile::load()
            .context("failed to load Radicle profile — is `rad auth` done?")?;

        info!(
            home = %profile.home().path().display(),
            did = %profile.did(),
            "Radicle profile loaded"
        );

        Ok(Self { profile, work_dir })
    }

    /// The node ID (public key) for this profile.
    pub fn node_id(&self) -> &PublicKey {
        self.profile.id()
    }

    /// The profile's DID.
    pub fn did(&self) -> Did {
        self.profile.did()
    }

    // ── Repo creation ──────────────────────────────────────────────

    /// Initialize a new Radicle repo for a task.
    ///
    /// Called by the relayer after receiving a 41000 event. Creates:
    /// - MANIFEST.json (constructed from event tags by the caller)
    /// - input/ directory with the provided files
    /// - output/ directory (empty, worker fills this)
    ///
    /// No verify/ directory — the verifier generates that after the worker submits.
    /// No verify_hash at creation — the verifier computes it later.
    ///
    /// Commits everything and calls `rad init` to publish to the network.
    pub fn init_task_repo(
        &self,
        name: &str,
        manifest_json: &str,
        input_files: &[InputFile],
    ) -> Result<WorkspaceInfo> {
        let repo_dir = self.work_dir.join(name);
        if repo_dir.exists() {
            bail!("repo directory already exists: {}", repo_dir.display());
        }

        // 1. Create directory structure (no verify/ — verifier adds that later)
        std::fs::create_dir_all(repo_dir.join("input"))?;
        std::fs::create_dir_all(repo_dir.join("output"))?;

        // 2. Write MANIFEST.json
        std::fs::write(repo_dir.join("MANIFEST.json"), manifest_json)?;
        info!("wrote MANIFEST.json");

        // 3. Write input files
        for file in input_files {
            let file_path = repo_dir.join("input").join(&file.path);
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&file_path, &file.content)?;
        }
        info!(count = input_files.len(), "wrote input files");

        // 4. git init + commit
        let git_repo = git2::Repository::init(&repo_dir)
            .with_context(|| format!("git init at {}", repo_dir.display()))?;

        let mut index = git_repo.index().context("get git index")?;
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .context("git add all")?;
        index.write().context("write index")?;

        let tree_id = index.write_tree().context("write tree")?;
        let tree = git_repo.find_tree(tree_id)?;
        let sig = git2::Signature::now("inlayer-relayer", "relayer@radicle")?;
        git_repo
            .commit(
                Some("HEAD"),
                &sig,
                &sig,
                &format!("Initial task: {}", name),
                &tree,
                &[],
            )
            .context("initial commit")?;

        // 5. rad init — publish to Radicle network
        let project_name = ProjectName::try_from(name)
            .map_err(|e| anyhow::anyhow!("invalid project name '{}': {}", name, e))?;

        let signer = self.profile.signer().context("get Radicle signer")?;

        let default_branch = radicle::git::fmt::refname!("main");
        let visibility = radicle::identity::doc::Visibility::default(); // Public

        let (rid, _doc, _refs) = radicle::rad::init(
            &git_repo,
            project_name,
            &format!("Task workspace: {}", name),
            default_branch,
            visibility,
            &*signer,
            &self.profile.storage,
        )
        .context("rad init failed")?;

        let rid_str = rid.to_string();
        info!(rid = %rid_str, "Radicle repo initialized");

        // 6. Announce to network (best-effort)
        if let Err(e) = self.announce_repo(rid) {
            warn!(error = %e, "failed to announce repo (non-fatal)");
        }

        Ok(WorkspaceInfo {
            rid: rid_str,
            path: repo_dir,
        })
    }

    /// Grant a Radicle DID access to a repo.
    ///
    /// Used by the relayer to notify the selected verifier that they should
    /// start seeding this repo. The verifier DID comes from __fastkv on the
    /// escrow contract.
    ///
    /// For v1, repos are public (cloneable by anyone). Access control is
    /// enforced by: only the designated verifier's verdict is accepted on-chain.
    /// The verifier is selected deterministically from verifier_set, so
    /// spoofing is impossible.
    ///
    /// The "grant" is really just pushing refs to the verifier node so they
    /// start seeding.
    pub fn grant_access(&self, rid: RepoId, verifier_nid: &PublicKey) -> Result<()> {
        let socket = self.profile.home().socket();
        let mut node = Node::new(socket);

        // Announce refs to the verifier specifically
        node.announce_refs_for(rid, Some(*verifier_nid))
            .context("announce refs to verifier")?;

        info!(rid = %rid, verifier = %verifier_nid, "repo pushed to verifier seed");
        Ok(())
    }

    // ── Network operations ─────────────────────────────────────────

    /// Announce a repo to the Radicle network so peers can discover it.
    fn announce_repo(&self, rid: RepoId) -> Result<()> {
        let socket = self.profile.home().socket();
        let mut node = Node::new(socket);

        node.add_inventory(rid).context("add_inventory")?;

        // Try to announce — best-effort
        let nid = node.nid().context("get node ID")?;
        let _ = node.announce_refs_for(rid, Some(nid));
        node.announce_inventory().context("announce inventory")?;

        info!(rid = %rid, "repo announced to network");
        Ok(())
    }

    /// Sync (fetch) a repo from the network.
    ///
    /// Must be called before checkout if the repo isn't in local storage.
    pub fn fetch_repo(&self, rid: RepoId, timeout_secs: u64) -> Result<()> {
        let socket = self.profile.home().socket();
        let mut node = Node::new(socket);
        let nid = node.nid().context("get node ID")?;

        // Find seeds
        let seeds = node
            .seeds_for(rid, [*self.profile.id()])
            .context("lookup seeds")?;

        if seeds.is_empty() {
            bail!("no seeds found for repo {}", rid);
        }

        // Fetch from first available seed
        let seed = seeds.iter().next().context("no seed available")?;

        let result = node
            .fetch(
                rid,
                seed.nid,
                std::time::Duration::from_secs(timeout_secs),
                None,
            )
            .context("fetch from seed")?;

        match result {
            radicle::node::FetchResult::Success { updated, .. } => {
                info!(rid = %rid, refs = updated.len(), "fetch succeeded");
                Ok(())
            }
            radicle::node::FetchResult::Failed { reason } => {
                bail!("fetch failed for {}: {}", rid, reason);
            }
        }
    }

    // ── Clone + checkout ────────────────────────────────────────────

    /// Clone a repo into `work_dir/{name}/`.
    ///
    /// Fetches from network → forks into local namespace → checks out working copy.
    pub fn clone_repo(&self, rid: RepoId, name: &str, fetch_timeout_secs: u64) -> Result<PathBuf> {
        let dest = self.work_dir.join(name);
        if dest.exists() {
            bail!("clone destination already exists: {}", dest.display());
        }

        // 1. Fetch from network
        self.fetch_repo(rid, fetch_timeout_secs)?;

        // 2. Fork into local namespace
        let signer = self.profile.signer().context("get signer for fork")?;
        radicle::rad::fork(rid, &*signer, &self.profile.storage).context("rad fork")?;

        // 3. Checkout working copy
        let _repo = radicle::rad::checkout(
            rid,
            self.profile.id(),
            &dest,
            &self.profile.storage,
            false, // not bare
        )
        .context("rad checkout")?;

        info!(rid = %rid, path = %dest.display(), "repo cloned");
        Ok(dest)
    }

    // ── Patches ─────────────────────────────────────────────────────

    /// List patches for a repo.
    pub fn list_patches(&self, rid: RepoId) -> Result<Vec<PatchSummary>> {
        let repo = self
            .profile
            .storage
            .repository(rid)
            .context("open repo for patch listing")?;
        let patches = self.profile.patches(&repo).context("open patch store")?;

        let mut out = Vec::new();
        for item in patches.list().context("list patches")? {
            let (id, patch): (radicle::cob::ObjectId, radicle::cob::patch::Patch) = item?;
            // Get the latest revision's head/base
            let (head, base) = patch
                .revisions()
                .last()
                .map(|(_, rev): (_, &radicle::cob::patch::Revision)| {
                    (rev.head().to_string(), rev.base().to_string())
                })
                .unwrap_or_default();

            out.push(PatchSummary {
                id: id.to_string(),
                title: patch.title().to_string(),
                state: format!("{:?}", patch.state()),
                head,
                base,
            });
        }
        Ok(out)
    }

    /// Checkout a specific patch into a working copy.
    ///
    /// Clones the repo (if needed), then sets up the patch branch.
    pub fn checkout_patch(
        &self,
        rid: RepoId,
        patch_id_str: &str,
        work_path: &Path,
    ) -> Result<git2::Repository> {
        // Ensure repo is fetched
        if self.profile.storage.repository(rid).is_err() {
            self.fetch_repo(rid, 60)?;
        }

        // Fork if not already forked
        let signer = self.profile.signer().context("get signer")?;
        let _ = radicle::rad::fork(rid, &*signer, &self.profile.storage);

        // Checkout working copy if not already present
        let git_repo = if work_path.exists() {
            git2::Repository::open(work_path).context("open existing checkout")?
        } else {
            radicle::rad::checkout(
                rid,
                self.profile.id(),
                work_path,
                &self.profile.storage,
                false,
            )
            .context("checkout working copy")?
        };

        // Find the patch and get its head OID
        let repo = self
            .profile
            .storage
            .repository(rid)
            .context("open storage repo")?;
        let patches = self.profile.patches(&repo).context("open patch store")?;

        let patch_id = ObjectId::from_str(patch_id_str).context("parse patch ID")?;
        let patch = patches
            .get(&patch_id)?
            .ok_or_else(|| anyhow::anyhow!("patch {} not found", patch_id_str))?;

        let (_, latest_rev) = patch
            .revisions()
            .last()
            .ok_or_else(|| anyhow::anyhow!("patch {} has no revisions", patch_id_str))?;

        let head_oid = latest_rev.head();

        // Set up patch upstream using the rad crate's REMOTE_NAME
        let remote = &*radicle::rad::REMOTE_NAME;

        let _branch = radicle::rad::setup_patch_upstream(
            &patch_id,
            head_oid,
            &git_repo,
            remote,
            true, // force
        )
        .context("setup patch upstream")?;

        // Drop the branch reference (which borrows git_repo) before returning it.
        drop(_branch);

        info!(patch = patch_id_str, head = %head_oid, "patch checked out");
        Ok(git_repo)
    }
}

// ── Directory hashing ──────────────────────────────────────────────────

/// Compute a deterministic SHA-256 hash of a directory.
///
/// Files are sorted by relative path. Each entry contributes:
/// `path_bytes || \0 || file_contents || \0`
///
/// The result is formatted as `sha256:<hex>`.
pub fn hash_directory(dir: &Path) -> Result<String> {
    if !dir.is_dir() {
        bail!("not a directory: {}", dir.display());
    }

    // Collect all files with their relative paths
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    collect_files(dir, dir, &mut entries)?;

    if entries.is_empty() {
        bail!("directory is empty: {}", dir.display());
    }

    // Deterministic hash: sorted by path, each entry hashed in sequence
    let mut hasher = sha2::Sha256::new();
    for (rel_path, content) in &entries {
        hasher.update(rel_path.as_bytes());
        hasher.update(&[0]);
        hasher.update(content);
        hasher.update(&[0]);
    }

    let hash = hasher.finalize();
    Ok(format!("sha256:{:x}", hash))
}

/// Recursively collect files in a directory, keyed by relative path.
fn collect_files(
    base: &Path,
    current: &Path,
    entries: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let dir =
        std::fs::read_dir(current).with_context(|| format!("read_dir: {}", current.display()))?;

    for entry in dir {
        let entry = entry?;
        let path = entry.path();
        let rel = path
            .strip_prefix(base)?
            .to_string_lossy()
            .replace('\\', "/"); // Normalize separators

        if path.is_dir() {
            // Skip hidden dirs (.git, .radicle, etc.)
            if rel.starts_with('.') {
                continue;
            }
            collect_files(base, &path, entries)?;
        } else if path.is_file() {
            // Skip hidden files
            let filename = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if filename.starts_with('.') {
                continue;
            }
            let content =
                std::fs::read(&path).with_context(|| format!("read: {}", path.display()))?;
            entries.insert(rel, content);
        }
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_directory_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // Create some files
        std::fs::write(dir.join("verify.sh"), "#!/bin/bash\nexit 0\n").unwrap();
        std::fs::write(dir.join("MANIFEST.json"), r#"{"method":"test_suite"}"#).unwrap();
        std::fs::create_dir_all(dir.join("subdir")).unwrap();
        std::fs::write(dir.join("subdir").join("helper.sh"), "echo hello\n").unwrap();

        let hash1 = hash_directory(dir).unwrap();
        let hash2 = hash_directory(dir).unwrap();
        assert_eq!(hash1, hash2, "hash must be deterministic");
        assert!(hash1.starts_with("sha256:"), "hash must be prefixed");
    }

    #[test]
    fn test_hash_directory_excludes_hidden() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        std::fs::write(dir.join("verify.sh"), "#!/bin/bash\nexit 0\n").unwrap();
        std::fs::write(dir.join(".hidden"), "should be ignored\n").unwrap();

        let hash_without = {
            let tmp2 = tempfile::tempdir().unwrap();
            std::fs::write(tmp2.path().join("verify.sh"), "#!/bin/bash\nexit 0\n").unwrap();
            hash_directory(tmp2.path()).unwrap()
        };

        let hash_with = hash_directory(dir).unwrap();
        assert_eq!(hash_without, hash_with, "hidden files must not affect hash");
    }

    #[test]
    fn test_hash_directory_empty_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let result = hash_directory(tmp.path());
        assert!(result.is_err(), "empty directory should fail");
    }

    #[test]
    fn test_hash_directory_not_dir_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("not-a-dir");
        std::fs::write(&file, "x").unwrap();
        let result = hash_directory(&file);
        assert!(result.is_err(), "file should fail");
    }

    #[test]
    fn test_hash_directory_sort_order() {
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();

        // Write same files in different order
        std::fs::write(tmp1.path().join("a.txt"), "aaa").unwrap();
        std::fs::write(tmp1.path().join("b.txt"), "bbb").unwrap();

        std::fs::write(tmp2.path().join("b.txt"), "bbb").unwrap();
        std::fs::write(tmp2.path().join("a.txt"), "aaa").unwrap();

        let h1 = hash_directory(tmp1.path()).unwrap();
        let h2 = hash_directory(tmp2.path()).unwrap();
        assert_eq!(h1, h2, "order of file creation must not matter");
    }
}
