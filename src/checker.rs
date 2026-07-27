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

    pub async fn suggest_safe_version(
        &mut self,
        ecosystem: &Ecosystem,
        package: &str,
    ) -> Result<CheckResult> {
        let metadata = match ecosystem {
            Ecosystem::Npm => {
                if self.npm_registry.is_none() {
                    self.npm_registry = Some(NpmRegistry::new());
                }
                self.npm_registry.as_ref().unwrap().resolve(package).await?
            }
            Ecosystem::Go => {
                if self.go_registry.is_none() {
                    self.go_registry = Some(GoRegistry::new());
                }
                self.go_registry.as_ref().unwrap().resolve(package).await?
            }
        };

        for version in metadata.versions.iter().rev().take(50) {
            let result = self.check(ecosystem, package, version).await?;
            if result.recommendation == Recommendation::Allow {
                return Ok(result);
            }
        }

        let mut result = self.check(ecosystem, package, "latest").await?;
        result.summary = format!(
            "No safe version found for {} {}. Latest version has {} vulnerabilities.",
            ecosystem, package, result.vulnerability_count
        );
        Ok(result)
    }

    pub async fn compare_versions(
        &mut self,
        ecosystem: &Ecosystem,
        package: &str,
        from_version: &str,
        to_version: &str,
    ) -> Result<CompareResult> {
        let from_result = self.check(ecosystem, package, from_version).await?;
        let to_result = self.check(ecosystem, package, to_version).await?;

        let risk_improved = to_result.risk_score < from_result.risk_score;

        let from_ids: std::collections::HashSet<&str> =
            from_result.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        let to_ids: std::collections::HashSet<&str> =
            to_result.vulnerabilities.iter().map(|v| v.id.as_str()).collect();

        let resolved: Vec<String> = from_ids.difference(&to_ids).map(|id| id.to_string()).collect();
        let added: Vec<String> = to_ids.difference(&from_ids).map(|id| id.to_string()).collect();

        let next_action = if risk_improved {
            "upgrade_to_target".to_string()
        } else if to_result.risk_score == from_result.risk_score {
            "no_change".to_string()
        } else {
            "downgrade_riskier".to_string()
        };

        Ok(CompareResult {
            ecosystem: ecosystem.to_string(),
            package: package.to_string(),
            from_version: from_version.to_string(),
            to_version: to_version.to_string(),
            from_risk_score: from_result.risk_score,
            to_risk_score: to_result.risk_score,
            risk_improved,
            recommendation: to_result.recommendation,
            next_action,
            resolved_vulnerabilities: resolved,
            added_vulnerabilities: added,
        })
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
