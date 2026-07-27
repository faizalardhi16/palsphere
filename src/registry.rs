use crate::types::{Ecosystem, PackageMetadata};
use anyhow::{Context, Result};
use serde::Deserialize;

// ── npm ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NpmResponse {
    name: Option<String>,
    #[serde(rename = "dist-tags")]
    dist_tags: Option<NpmDistTags>,
    versions: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct NpmDistTags {
    latest: Option<String>,
}

pub struct NpmRegistry {
    client: reqwest::Client,
}

impl NpmRegistry {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn resolve(&self, package: &str) -> Result<PackageMetadata> {
        let url = format!("https://registry.npmjs.org/{}", package);
        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .context(format!("Failed to resolve npm package: {}", package))?;

        let npm: NpmResponse = response
            .json()
            .await
            .context("Failed to parse npm registry response")?;

        let name = npm.name.unwrap_or_else(|| package.to_string());
        let latest = npm
            .dist_tags
            .and_then(|dt| dt.latest)
            .unwrap_or_else(|| "unknown".to_string());

        let versions: Vec<String> = npm
            .versions
            .map(|v| v.keys().cloned().collect())
            .unwrap_or_default();

        Ok(PackageMetadata {
            name,
            ecosystem: Ecosystem::Npm,
            latest_version: latest,
            versions,
        })
    }
}

// ── Go ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GoProxyResponse {
    #[serde(rename = "Version")]
    version: String,
}

pub struct GoRegistry {
    client: reqwest::Client,
}

impl GoRegistry {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn resolve(&self, package: &str) -> Result<PackageMetadata> {
        // Go module proxy: https://proxy.golang.org/<module>/@latest
        let url = format!("https://proxy.golang.org/{}/@latest", package);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context(format!("Failed to resolve Go package: {}", package))?;

        let proxy: GoProxyResponse = response
            .json()
            .await
            .context("Failed to parse Go proxy response")?;

        // Fetch list of versions
        let versions_url = format!("https://proxy.golang.org/{}/@v/list", package);
        let versions_response = self
            .client
            .get(&versions_url)
            .send()
            .await
            .context("Failed to fetch Go versions list")?;

        let versions_text = versions_response.text().await.unwrap_or_default();
        let versions: Vec<String> = versions_text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();

        Ok(PackageMetadata {
            name: package.to_string(),
            ecosystem: Ecosystem::Go,
            latest_version: proxy.version,
            versions,
        })
    }
}
