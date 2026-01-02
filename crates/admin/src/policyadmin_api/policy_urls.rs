use crate::utils::json::JsonNode;
use anyhow::{Context, Result, anyhow};
use reqwest::{
    Client,
    header::{ETAG, LAST_MODIFIED},
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, time::sleep};

/* -----------------------------------------------------------------------------
 * Policy poller:
 *
 * Expected config schema (config.json):
 *
 * {
 *   "policy-name": {
 *     "url": "https://example/policy.tar.gz",
 *     "vms": ["vm1","vm2"],
 *     "poll_interval_secs": 30,
 *   }
 * }
 *
 * -------------------------------------------------------------------------- */

const CONFIG_FILE_NAME: &str = "config.json";

/* -----------------------------------------------------------------------------
 * Types
 * -------------------------------------------------------------------------- */

#[derive(Clone)]
struct PolicyUrlMonitor {
    client: Client,
    policies: Arc<Mutex<JsonNode>>,
    config_path: PathBuf,
    output_dir: PathBuf,
}

impl PolicyUrlMonitor {
    /* -------------------------------------------------------------------------
     * new (Constructor)
     *
     *  Constructor that selects a writable config source.
     *
     *  Parameters:
     *    policy_path - writable directory where config.json and downloaded policies will live
     *    config_path - read-only path to an existing JSON config file
     *
     *  Behavior:
     *    - If <policy_path>/config.json exists, load that.
     *    - Otherwise, load config from config_path.
     *    - Always persist the loaded config into <policy_path>/config.json
     *      (because config_path is read-only).
     * ---------------------------------------------------------------------- */
    fn new(policy_path: impl AsRef<Path>, config_path: impl AsRef<Path>) -> Result<Self> {
        let local_dir = policy_path.as_ref();
        fs::create_dir_all(local_dir)
            .with_context(|| format!("Failed to create local policy directory {:?}", local_dir))?;

        let local_config_path = local_dir.join(CONFIG_FILE_NAME);
        let mut new_config_path = if local_config_path.exists() {
            local_config_path.clone()
        } else if config_path.as_ref().exists() {
            config_path.clone()
        } else {
            return Err(anyhow!("Config path not found: {:?}", config_path.as_ref()));
        };

        let policies = Arc::new(RwLock::new(JsonNode::new(new_config_path.clone())))?;

        Ok(Self {
            client: Client::new(),
            policies: Arc::new(Mutex::new(policies)),
            config_path: local_config_path,
            output_dir: policy_path.into(),
        })
    }

    /* -------------------------------------------------------------------------
     * run
     *
     *  Spawns a polling task per policy and waits forever.
     * ---------------------------------------------------------------------- */
    async fn run(self) -> Result<()> {
        let mut handles = Vec::new();
        let policy_names = {
            let policies = self.policies.lock().await;
            policies.get_keys(&["policies"]).into_iter().collect()
        };

        for policy_name in policy_names {
            let poller = self.clone();
            let handle = tokio::spawn(async move {
                if let Err(err) = poller.monitor_url(policy_name.clone()).await {
                    eprintln!("Error in poller task for {}: {:#}", policy_name, err);
                }
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.await;
        }

        Ok(())
    }

    /* -------------------------------------------------------------------------
     * monitor_url
     *
     *  Infinite loop that polls a single policy on its configured interval.
     * ---------------------------------------------------------------------- */
    async fn monitor_url(&self, policy_name: String) -> Result<()> {
        let (url, head, vms, interval) = {
            let policies = self.policies.lock().await;

            let url = node.get_field(&[policy_name, "url"]);
            let head = node.get_field(&[policy_name, "head"]);
            let vms = node.get_field(&[policy_name, "vms"]);
            let interval = node
                .get_field(&[policy_name, "poll_interval_secs"])
                .parse::<u64>()
                .unwrap_or(60);

            (url, head, vms, interval)
        };

        if url.trim().is_empty() {
            error!("Policy {policy_name}: missing/empty 'url'; skipping.");
            return Ok(());
        }

        loop {
            let mut current_head = head.clone();

            match self.poll_once(&url, &head).await? {
                Some((new_head, policy_file)) => {
                    current_head = new_head;
                    for vm in &vms {}

                    self.on_policy_updated(&policy_name).await;
                }
                None => {
                    continue;
                }
            }

            sleep(Duration::from_secs(interval)).await;
        }
    }

    /* -------------------------------------------------------------------------
     * poll_once
     *
     *  One iteration:
     *   - HEAD to detect change (ETag / Last-Modified)
     *   - GET if changed
     *   - hash fallback if needed
     *   - save file + update head_ref + persist config.json
     *   - call on_policy_updated hook
     * ---------------------------------------------------------------------- */
    async fn poll_once(&self, url: &str, current_head: &str) -> Result<Option<(String, String)>> {
        let head_resp = self.client.head(&url).send().await?;
        if !head_resp.status().is_success() {
            eprintln!(
                "HEAD {} ({}) returned non-success status: {}",
                policy_name,
                url,
                head_resp.status()
            );
            return Ok(None);
        }

        let headers = head_resp.headers();
        let mut new_head: Option<String> = None;

        if let Some(etag_val) = headers.get(ETAG) {
            if let Ok(s) = etag_val.to_str() {
                new_head = Some(format!("etag:{s}"));
            }
        }

        if new_head.is_none() {
            if let Some(lm_val) = headers.get(LAST_MODIFIED) {
                if let Ok(s) = lm_val.to_str() {
                    new_head = Some(format!("last-modified:{s}"));
                }
            }
        }

        let need_hash = new_head.is_none();

        if !need_hash && new_head == current_head && current_head.is_some() {
            println!("No change → {policy_name}");
            return Ok(None);
        }

        println!("Change detected for {policy_name}, downloading…");

        /* --- GET --- */
        let get_resp = self.client.get(&url).send().await?;
        if !get_resp.status().is_success() {
            eprintln!(
                "GET {} ({}) returned non-success status: {}",
                policy_name,
                url,
                get_resp.status()
            );
            return Ok(None);
        }

        let body = get_resp.bytes().await?;

        let final_head = if need_hash {
            let mut hasher = Sha256::new();
            hasher.update(&body);
            Some(format!("sha256:{:x}", hasher.finalize()))
        } else {
            new_head
        };

        /* --- Write file --- */
        let policy_file = url.split('/').last().unwrap_or("unknown_policy.bin");
        let dest = self.output_dir.join(policy_name).join(policy_file);

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }

        fs::write(&dest, &body).with_context(|| format!("Failed to write file {:?}", dest))?;

        println!("Saved {policy_name} to {:?}", dest);

        Ok(new_head, policy_file)
    }

    /* -------------------------------------------------------------------------
     * Helpers (JsonNode typed reads)
     * ---------------------------------------------------------------------- */

    async fn get_u64(&self, policy_name: &str, path: &[&str]) -> Option<u64> {
        let guard = self.policies.lock().await;
        let node = guard.get(policy_name)?;
        Self::node_get_u64(node, path)
    }

    fn node_get_string(node: &JsonNode, path: &[&str]) -> Option<String> {
        let v = node.get_value(path)?;
        match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            other => Some(other.to_string()),
        }
    }

    fn node_get_u64(node: &JsonNode, path: &[&str]) -> Option<u64> {
        let v = node.get_value(path)?;
        match v {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        }
    }

    fn node_get_string_vec(node: &JsonNode, path: &[&str]) -> Option<Vec<String>> {
        let v = node.get_value(path)?;
        let arr = v.as_array()?;
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            match item {
                Value::String(s) => out.push(s.clone()),
                other => out.push(other.to_string()),
            }
        }
        Some(out)
    }
}

/* -----------------------------------------------------------------------------
 * main
 *
 * Example usage:
 *  - policy_path: writable dir (e.g. "/var/lib/policies")
 *  - config_path:    read-only config file shipped in image (e.g. "/etc/policies/config.json")
 * -------------------------------------------------------------------------- */
/*
#[tokio::main]
async fn main() -> Result<()> {
    let policy_path = "./policy-state";
    let config_path = "./ro-config.json";
    let output_dir = "./pulled-policies";

    let poller = PolicyUrlMonitor::new(policy_path, config_path, output_dir)?;
    poller.run().await
}
*/
