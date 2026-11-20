//! One-click cloud access: an **ephemeral credentialed shell**.
//!
//! Open a terminal that is already authenticated to AWS, GCP, Azure or a
//! Kubernetes cluster, without the credentials ever touching the user's real
//! config files, shell history, or any command line.
//!
//! ## How it works
//!
//! Every provider here supports two mechanisms that make this clean:
//!
//!   1. **Environment variables.** Every official SDK, the CLIs, Terraform,
//!      Pulumi and kubectl all read credentials from the environment before
//!      they look at a config file. Keyring sets them in the child process's
//!      environment block, which — unlike a command line — is not enumerable
//!      from the process list.
//!   2. **Config redirection.** `AWS_SHARED_CREDENTIALS_FILE`, `CLOUDSDK_CONFIG`,
//!      `KUBECONFIG` and `AZURE_CONFIG_DIR` all move a tool's entire notion of
//!      "where my config lives" to a directory of our choosing. So the session
//!      writes its state into a temp directory that Keyring owns and purges,
//!      instead of into `~/.aws` where it would outlive the session and
//!      quietly become the machine's default identity.
//!
//! That second point is the one people miss. `gcloud auth activate-service-account`
//! without `CLOUDSDK_CONFIG` set does not open a session — it *changes who you
//! are* on that machine, permanently, until someone remembers to revoke it.
//!
//! ## What is deliberately not done
//!
//! `az login --service-principal -p <secret>` puts the client secret on a
//! command line. It is the documented way to do it and it is wrong, for the
//! same reason `cmdkey /pass:` was rejected in D-33. Azure therefore gets
//! environment variables only — which is what `EnvironmentCredential` in every
//! Azure SDK, and Terraform's azurerm provider, actually read. The Azure CLI
//! itself will still prompt; the toast says so rather than pretending
//! otherwise.
//!
//! ## Lifetime
//!
//! The temp config directory is registered with the same `TempRegistry` that
//! handles extracted SSH keys, so it is destroyed on vault lock, on exit, and
//! at its TTL — whichever comes first. Closing the terminal does not clean it
//! up, because Keyring cannot observe that; the TTL is what bounds it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{AppError, Result};

use super::terminal::Launch;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    Kubernetes,
}

impl CloudProvider {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "aws" | "amazon" | "amazon web services" => Some(CloudProvider::Aws),
            "gcp" | "google" | "google cloud" | "gce" => Some(CloudProvider::Gcp),
            "azure" | "microsoft azure" | "az" => Some(CloudProvider::Azure),
            "kubernetes" | "k8s" | "kubectl" => Some(CloudProvider::Kubernetes),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "aws",
            CloudProvider::Gcp => "gcp",
            CloudProvider::Azure => "azure",
            CloudProvider::Kubernetes => "kubernetes",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "AWS",
            CloudProvider::Gcp => "Google Cloud",
            CloudProvider::Azure => "Azure",
            CloudProvider::Kubernetes => "Kubernetes",
        }
    }

    /// The command run to prove the session works. Read-only, cheap, and
    /// universally available — a shell that opens and does nothing leaves the
    /// user wondering whether it worked.
    pub fn verify_command(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "aws sts get-caller-identity",
            CloudProvider::Gcp => "gcloud auth list",
            CloudProvider::Azure => "az account show",
            CloudProvider::Kubernetes => "kubectl config current-context",
        }
    }
}

/// The plaintext a provider needs, gathered from a record's fields.
///
/// Every value is `Zeroizing`. This struct is built, consumed by
/// [`build_launch`], and dropped inside a single IPC command.
#[derive(Debug, Default)]
pub struct CloudCredentials {
    pub values: BTreeMap<String, Zeroizing<String>>,
}

impl CloudCredentials {
    pub fn insert(&mut self, key: &str, value: impl Into<String>) {
        let value = value.into();
        if !value.trim().is_empty() {
            self.values.insert(key.to_string(), Zeroizing::new(value));
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|v| v.as_str())
    }

    pub fn require(&self, key: &str, human: &str) -> Result<&str> {
        self.get(key)
            .ok_or_else(|| AppError::invalid(format!("This record has no {human}.")))
    }
}

/// A prepared session, ready to spawn.
#[derive(Debug)]
pub struct CloudSession {
    pub launch: Launch,
    /// The isolated config directory, if the provider needed one.
    pub config_dir: Option<PathBuf>,
    pub provider: CloudProvider,
    /// Shown in the toast. Never contains a secret.
    pub summary: String,
    /// True when the provider's own CLI cannot be fully non-interactive with
    /// environment variables alone. Surfaced to the user rather than hidden.
    pub cli_may_prompt: bool,
}

/// Build the launch for a provider.
///
/// `scratch` is a directory Keyring owns and will purge. Nothing is written
/// outside it.
pub fn build_launch(
    provider: CloudProvider,
    creds: &CloudCredentials,
    scratch: &std::path::Path,
    keep_open: bool,
) -> Result<CloudSession> {
    let mut launch = Launch {
        keep_open,
        ..Default::default()
    };

    let config_dir;
    let mut cli_may_prompt = false;
    let summary;

    match provider {
        CloudProvider::Aws => {
            let key_id = creds.require("access_key_id", "access key ID")?;
            let secret = creds.require("secret_access_key", "secret access key")?;

            launch.env.insert(
                "AWS_ACCESS_KEY_ID".into(),
                Zeroizing::new(key_id.to_string()),
            );
            launch.env.insert(
                "AWS_SECRET_ACCESS_KEY".into(),
                Zeroizing::new(secret.to_string()),
            );
            if let Some(token) = creds.get("session_token") {
                launch.env.insert(
                    "AWS_SESSION_TOKEN".into(),
                    Zeroizing::new(token.to_string()),
                );
            }
            if let Some(region) = creds.get("region") {
                // Both, because different tools read different ones and the
                // asymmetry has cost everyone an afternoon at some point.
                launch
                    .env
                    .insert("AWS_REGION".into(), Zeroizing::new(region.to_string()));
                launch.env.insert(
                    "AWS_DEFAULT_REGION".into(),
                    Zeroizing::new(region.to_string()),
                );
            }

            // Point the shared config elsewhere so the session cannot pick up
            // — or write to — the user's real profile.
            let dir = scratch.join("aws");
            std::fs::create_dir_all(&dir)
                .map_err(|_| AppError::internal("could not create the AWS scratch directory"))?;
            launch.env.insert(
                "AWS_SHARED_CREDENTIALS_FILE".into(),
                Zeroizing::new(dir.join("credentials").to_string_lossy().into_owned()),
            );
            launch.env.insert(
                "AWS_CONFIG_FILE".into(),
                Zeroizing::new(dir.join("config").to_string_lossy().into_owned()),
            );
            config_dir = Some(dir);

            summary = match creds.get("region") {
                Some(r) => format!("AWS session ({r})"),
                None => "AWS session".to_string(),
            };
        }

        CloudProvider::Gcp => {
            // GCP authenticates with a service-account JSON key. It has to be
            // a file: `GOOGLE_APPLICATION_CREDENTIALS` takes a path, and there
            // is no environment-variable form of the key itself.
            let key_json = creds.require("service_account_json", "service account key")?;

            let dir = scratch.join("gcloud");
            std::fs::create_dir_all(&dir)
                .map_err(|_| AppError::internal("could not create the gcloud scratch directory"))?;

            let key_path = dir.join("service-account.json");
            write_locked_down(&key_path, key_json.as_bytes())?;

            launch.env.insert(
                "GOOGLE_APPLICATION_CREDENTIALS".into(),
                Zeroizing::new(key_path.to_string_lossy().into_owned()),
            );
            // Isolate gcloud's entire config, so `activate-service-account`
            // changes this session's identity and nothing else's.
            launch.env.insert(
                "CLOUDSDK_CONFIG".into(),
                Zeroizing::new(dir.to_string_lossy().into_owned()),
            );
            if let Some(project) = creds.get("project_id") {
                launch.env.insert(
                    "CLOUDSDK_CORE_PROJECT".into(),
                    Zeroizing::new(project.to_string()),
                );
                launch.env.insert(
                    "GOOGLE_CLOUD_PROJECT".into(),
                    Zeroizing::new(project.to_string()),
                );
            }

            // Only a path on this command line, never the key.
            launch.argv = vec![
                "gcloud".into(),
                "auth".into(),
                "activate-service-account".into(),
                "--key-file".into(),
                key_path.to_string_lossy().into_owned(),
            ];

            config_dir = Some(dir);
            summary = match creds.get("project_id") {
                Some(p) => format!("Google Cloud session ({p})"),
                None => "Google Cloud session".to_string(),
            };
        }

        CloudProvider::Azure => {
            let client_id = creds.require("client_id", "client ID")?;
            let tenant_id = creds.require("tenant_id", "tenant ID")?;
            let client_secret = creds.require("client_secret", "client secret")?;

            launch.env.insert(
                "AZURE_CLIENT_ID".into(),
                Zeroizing::new(client_id.to_string()),
            );
            launch.env.insert(
                "AZURE_TENANT_ID".into(),
                Zeroizing::new(tenant_id.to_string()),
            );
            launch.env.insert(
                "AZURE_CLIENT_SECRET".into(),
                Zeroizing::new(client_secret.to_string()),
            );
            // Terraform's azurerm provider reads ARM_* rather than AZURE_*.
            launch
                .env
                .insert("ARM_CLIENT_ID".into(), Zeroizing::new(client_id.to_string()));
            launch.env.insert(
                "ARM_TENANT_ID".into(),
                Zeroizing::new(tenant_id.to_string()),
            );
            launch.env.insert(
                "ARM_CLIENT_SECRET".into(),
                Zeroizing::new(client_secret.to_string()),
            );
            if let Some(subscription) = creds.get("subscription_id") {
                launch.env.insert(
                    "AZURE_SUBSCRIPTION_ID".into(),
                    Zeroizing::new(subscription.to_string()),
                );
                launch.env.insert(
                    "ARM_SUBSCRIPTION_ID".into(),
                    Zeroizing::new(subscription.to_string()),
                );
            }

            let dir = scratch.join("azure");
            std::fs::create_dir_all(&dir)
                .map_err(|_| AppError::internal("could not create the Azure scratch directory"))?;
            launch.env.insert(
                "AZURE_CONFIG_DIR".into(),
                Zeroizing::new(dir.to_string_lossy().into_owned()),
            );
            config_dir = Some(dir);

            // See the module banner: `az login --service-principal -p` is not
            // used, on purpose. SDKs and Terraform are fully authenticated;
            // the `az` CLI itself may still ask.
            cli_may_prompt = true;
            summary = "Azure session (SDKs and Terraform authenticated)".to_string();
        }

        CloudProvider::Kubernetes => {
            let kubeconfig = creds.require("kubeconfig", "kubeconfig")?;

            let dir = scratch.join("kube");
            std::fs::create_dir_all(&dir)
                .map_err(|_| AppError::internal("could not create the kube scratch directory"))?;
            let path = dir.join("config");
            write_locked_down(&path, kubeconfig.as_bytes())?;

            launch.env.insert(
                "KUBECONFIG".into(),
                Zeroizing::new(path.to_string_lossy().into_owned()),
            );
            if let Some(ns) = creds.get("namespace") {
                launch
                    .env
                    .insert("KEYRING_NAMESPACE".into(), Zeroizing::new(ns.to_string()));
                launch.argv = vec![
                    "kubectl".into(),
                    "config".into(),
                    "set-context".into(),
                    "--current".into(),
                    format!("--namespace={ns}"),
                ];
            }

            config_dir = Some(dir);
            summary = match creds.get("cluster") {
                Some(c) => format!("Kubernetes session ({c})"),
                None => "Kubernetes session".to_string(),
            };
        }
    }

    launch.title = Some(summary.clone());

    // Every provider ends with the same shape: run whatever setup it needs,
    // then leave an interactive shell. If there is no setup command, the
    // shell alone is the session.
    if launch.argv.is_empty() {
        launch.argv = vec!["cmd".into(), "/c".into(), "ver".into()];
    }

    Ok(CloudSession {
        launch,
        config_dir,
        provider,
        summary,
        cli_may_prompt,
    })
}

/// Write a credential file and restrict it to the current user.
///
/// Same reasoning as the SSH key case (D-31): a file created under
/// `%LOCALAPPDATA%` still inherits ACEs from its parent. `kubectl` does not
/// check permissions the way OpenSSH does, but a kubeconfig with a cluster
/// admin token in it deserves the same treatment regardless of whether a tool
/// enforces it.
fn write_locked_down(path: &std::path::Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)
        .map_err(|_| AppError::internal("could not write the credential file"))?;
    super::ssh::restrict_to_current_user(path)?;
    Ok(())
}

/// Where a session's scratch directories live.
///
/// Under the extraction directory, so the existing registry sweeps it.
pub fn scratch_root(session_id: &str) -> Result<PathBuf> {
    let dir = super::tempfile::TempRegistry::dir()?
        .join("cloud")
        .join(session_id);
    std::fs::create_dir_all(&dir)
        .map_err(|_| AppError::internal("could not create the cloud scratch directory"))?;
    Ok(dir)
}

/// Default lifetime of a cloud session's scratch directory.
pub fn default_ttl() -> Duration {
    Duration::from_secs(900)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn aws_puts_every_secret_in_the_environment_and_none_in_argv() {
        let dir = scratch();
        let mut creds = CloudCredentials::default();
        creds.insert("access_key_id", "AKIAIOSFODNN7EXAMPLE");
        creds.insert(
            "secret_access_key",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        creds.insert("region", "eu-west-1");

        let session = build_launch(CloudProvider::Aws, &creds, dir.path(), true).unwrap();

        assert_eq!(
            session.launch.env.get("AWS_ACCESS_KEY_ID").unwrap().as_str(),
            "AKIAIOSFODNN7EXAMPLE"
        );
        assert!(session.launch.env.contains_key("AWS_SECRET_ACCESS_KEY"));
        // Both region variables, because tools disagree about which to read.
        assert!(session.launch.env.contains_key("AWS_REGION"));
        assert!(session.launch.env.contains_key("AWS_DEFAULT_REGION"));

        let argv = session.launch.argv.join(" ");
        assert!(!argv.contains("wJalrXUtnFEMI"), "secret must not reach argv");
        assert!(!argv.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn aws_redirects_the_shared_credentials_file_away_from_the_real_profile() {
        let dir = scratch();
        let mut creds = CloudCredentials::default();
        creds.insert("access_key_id", "x");
        creds.insert("secret_access_key", "y");

        let session = build_launch(CloudProvider::Aws, &creds, dir.path(), true).unwrap();
        let redirected = session
            .launch
            .env
            .get("AWS_SHARED_CREDENTIALS_FILE")
            .unwrap()
            .to_string();
        assert!(redirected.starts_with(&dir.path().to_string_lossy().to_string()));
        assert!(!redirected.contains(".aws"));
    }

    #[test]
    fn a_missing_required_field_names_what_is_missing() {
        let dir = scratch();
        let creds = CloudCredentials::default();
        let err = build_launch(CloudProvider::Aws, &creds, dir.path(), true).unwrap_err();
        assert!(err.message.contains("access key ID"));
    }

    #[test]
    fn gcp_writes_the_key_to_a_file_and_only_the_path_reaches_argv() {
        let dir = scratch();
        let mut creds = CloudCredentials::default();
        let key = r#"{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----AAAA"}"#;
        creds.insert("service_account_json", key);
        creds.insert("project_id", "my-project");

        let session = build_launch(CloudProvider::Gcp, &creds, dir.path(), true).unwrap();

        let argv = session.launch.argv.join(" ");
        assert!(argv.contains("activate-service-account"));
        assert!(!argv.contains("BEGIN PRIVATE KEY"), "key must not reach argv");

        // CLOUDSDK_CONFIG is the difference between a session and permanently
        // changing who this machine is.
        assert!(session.launch.env.contains_key("CLOUDSDK_CONFIG"));

        let written = std::fs::read_to_string(dir.path().join("gcloud/service-account.json"))
            .expect("key file should exist");
        assert_eq!(written, key);
    }

    #[test]
    fn azure_never_builds_an_az_login_command_line() {
        let dir = scratch();
        let mut creds = CloudCredentials::default();
        creds.insert("client_id", "cid");
        creds.insert("tenant_id", "tid");
        creds.insert("client_secret", "super-secret-value");

        let session = build_launch(CloudProvider::Azure, &creds, dir.path(), true).unwrap();

        let argv = session.launch.argv.join(" ");
        assert!(!argv.contains("super-secret-value"));
        assert!(
            !argv.contains("--service-principal"),
            "az login -p is deliberately not used (D-33 reasoning)"
        );
        assert!(session.cli_may_prompt, "the UI must be told the CLI may ask");

        // Terraform reads ARM_*, the SDKs read AZURE_*. Both are set.
        assert!(session.launch.env.contains_key("ARM_CLIENT_SECRET"));
        assert!(session.launch.env.contains_key("AZURE_CLIENT_SECRET"));
    }

    #[test]
    fn kubernetes_isolates_the_kubeconfig() {
        let dir = scratch();
        let mut creds = CloudCredentials::default();
        creds.insert("kubeconfig", "apiVersion: v1\nkind: Config\n");
        creds.insert("namespace", "production");

        let session = build_launch(CloudProvider::Kubernetes, &creds, dir.path(), true).unwrap();
        let kubeconfig = session.launch.env.get("KUBECONFIG").unwrap().to_string();
        assert!(kubeconfig.starts_with(&dir.path().to_string_lossy().to_string()));
        assert!(session.launch.argv.join(" ").contains("--namespace=production"));
    }

    #[test]
    fn provider_names_parse_the_way_people_actually_type_them() {
        assert_eq!(CloudProvider::parse("AWS"), Some(CloudProvider::Aws));
        assert_eq!(
            CloudProvider::parse("Google Cloud"),
            Some(CloudProvider::Gcp)
        );
        assert_eq!(CloudProvider::parse("k8s"), Some(CloudProvider::Kubernetes));
        assert_eq!(CloudProvider::parse("digitalocean"), None);
    }
}
