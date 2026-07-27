use crate::types::{Ecosystem, Vulnerability, Severity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

#[derive(Debug, Serialize, Deserialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsvQuery {
    #[serde(rename = "package")]
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    database_specific: Option<serde_json::Value>,
    affected: Option<Vec<OsvAffected>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    vulns: Option<Vec<OsvVuln>>,
}

fn map_severity(vuln: &OsvVuln) -> Option<Severity> {
    // Check database_specific first (GitHub Advisory DB format)
    if let Some(db_specific) = &vuln.database_specific {
        if let Some(gh_severity) = db_specific.get("severity").and_then(|s| s.as_str()) {
            return match gh_severity {
                "CRITICAL" => Some(Severity::Critical),
                "HIGH" => Some(Severity::High),
                "MODERATE" => Some(Severity::Medium),
                "LOW" => Some(Severity::Low),
                _ => Some(Severity::Unknown),
            };
        }
    }
    // Fall back to CVSS scores
    if let Some(severities) = &vuln.severity {
        for s in severities {
            if s.severity_type == "CVSS_V3" {
                if let Ok(score) = s.score.parse::<f64>() {
                    return Some(if score >= 9.0 {
                        Severity::Critical
                    } else if score >= 7.0 {
                        Severity::High
                    } else if score >= 4.0 {
                        Severity::Medium
                    } else {
                        Severity::Low
                    });
                }
            }
        }
    }
    None
}

fn extract_fixed_versions(vuln: &OsvVuln) -> Vec<String> {
    let mut fixed = Vec::new();
    if let Some(affected_list) = &vuln.affected {
        for affected in affected_list {
            if let Some(ranges) = &affected.ranges {
                for range in ranges {
                    for event in &range.events {
                        if let Some(fixed_ver) = &event.fixed {
                            fixed.push(fixed_ver.clone());
                        }
                    }
                }
            }
        }
    }
    fixed
}

pub struct OsvClient {
    client: reqwest::Client,
}

impl OsvClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn check(
        &self,
        ecosystem: &Ecosystem,
        package: &str,
        version: &str,
    ) -> Result<Vec<Vulnerability>> {
        let query = OsvQuery {
            package: OsvPackage {
                name: package.to_string(),
                ecosystem: ecosystem.to_string(),
            },
            version: version.to_string(),
        };

        let response = self
            .client
            .post(OSV_QUERY_URL)
            .json(&query)
            .send()
            .await
            .context("Failed to query OSV API")?;

        let osv_response: OsvResponse = response
            .json()
            .await
            .context("Failed to parse OSV response")?;

        let vulns = osv_response.vulns.unwrap_or_default();
        let mut results = Vec::new();

        for vuln in &vulns {
            results.push(Vulnerability {
                id: vuln.id.clone(),
                summary: vuln.summary.clone(),
                severity: map_severity(vuln),
                fixed_versions: extract_fixed_versions(vuln),
                advisory_url: Some(format!(
                    "https://osv.dev/vulnerability/{}",
                    vuln.id
                )),
            });
        }

        Ok(results)
    }
}
