use crate::advisory::OsvClient;
use crate::registry::{GoRegistry, NpmRegistry};
use crate::types::*;
use anyhow::Result;
use chrono::Utc;

pub struct Checker {
    osv: OsvClient,
    npm_registry: Option<NpmRegistry>,
    go_registry: Option<GoRegistry>,
}

impl Checker {
    pub fn new() -> Self {
        Self {
            osv: OsvClient::new(),
            npm_registry: None,
            go_registry: None,
        }
    }

    pub async fn check(
        &mut self,
        ecosystem: &Ecosystem,
        package: &str,
        version: &str,
    ) -> Result<CheckResult> {
        // Resolve version if "latest"
        let resolved_version = if version == "latest" {
            self.resolve_latest(ecosystem, package).await?
        } else {
            version.to_string()
        };

        // Fetch vulnerabilities from OSV
        let vulnerabilities = self
            .osv
            .check(ecosystem, package, &resolved_version)
            .await?;

        let vuln_count = vulnerabilities.len();
        let known_found = vuln_count > 0;

        // Determine highest severity
        let highest_severity = vulnerabilities
            .iter()
            .filter_map(|v| v.severity.clone())
            .max();

        // Determine recommendation
        let recommendation = match &highest_severity {
            Some(Severity::Critical) | Some(Severity::High) => Recommendation::Block,
            Some(Severity::Medium) | Some(Severity::Unknown) => Recommendation::Review,
            Some(Severity::Low) => Recommendation::Allow,
            None => Recommendation::Allow,
        };

        let safe = recommendation == Recommendation::Allow;
        let risk_score = calculate_risk_score(&vulnerabilities);

        let reason = if known_found {
            format!("Found {} known vulnerability records.", vuln_count)
        } else {
            "No known vulnerabilities found in OSV database.".to_string()
        };

        let summary = if known_found {
            let sev = highest_severity
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            format!(
                "{} {} version {} has {} known vulnerabilities, including {} severity. {} this version.",
                ecosystem, package, resolved_version, vuln_count, sev,
                match recommendation {
                    Recommendation::Block => "Block",
                    Recommendation::Review => "Review",
                    Recommendation::Allow => "Allow",
                    Recommendation::Unknown => "Investigate",
                }
            )
        } else {
            format!(
                "{} {} version {} has no known vulnerabilities.",
                ecosystem, package, resolved_version
            )
        };

        Ok(CheckResult {
            ecosystem: ecosystem.to_string(),
            package: package.to_string(),
            version: resolved_version,
            latest_version: None,
            known_vulnerabilities_found: known_found,
            safe_to_use: safe,
            risk_score,
            recommendation,
            reason,
            summary,
            vulnerability_count: vuln_count,
            highest_severity,
            vulnerabilities,
            checked_at: Utc::now().to_rfc3339(),
        })
    }

    async fn resolve_latest(
        &mut self,
        ecosystem: &Ecosystem,
        package: &str,
    ) -> Result<String> {
        match ecosystem {
            Ecosystem::Npm => {
                if self.npm_registry.is_none() {
                    self.npm_registry = Some(NpmRegistry::new());
                }
                let meta = self.npm_registry.as_ref().unwrap().resolve(package).await?;
                Ok(meta.latest_version)
            }
            Ecosystem::Go => {
                if self.go_registry.is_none() {
                    self.go_registry = Some(GoRegistry::new());
                }
                let meta = self.go_registry.as_ref().unwrap().resolve(package).await?;
                Ok(meta.latest_version)
            }
        }
    }
}

fn calculate_risk_score(vulns: &[Vulnerability]) -> u8 {
    if vulns.is_empty() {
        return 0;
    }
    let max_severity = vulns
        .iter()
        .filter_map(|v| v.severity.as_ref())
        .max()
        .map(|s| severity_rank(s))
        .unwrap_or(2);
    let count_factor = (vulns.len() as u8).min(10) * 5;
    let base = max_severity * 20;
    (base + count_factor).min(100)
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Unknown => 2,
    }
}
