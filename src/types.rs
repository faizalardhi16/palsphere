use serde::{Deserialize, Serialize};

/// Supported ecosystems
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "Go")]
    Go,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::Go => write!(f, "Go"),
        }
    }
}

/// Recommendation based on highest severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Recommendation {
    Block,
    Review,
    Allow,
    Unknown,
}

/// Severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("{:?}", self);
        write!(f, "{}", s.to_lowercase())
    }
}

/// A single vulnerability from OSV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: Option<String>,
    pub severity: Option<Severity>,
    pub fixed_versions: Vec<String>,
    pub advisory_url: Option<String>,
}

/// Package metadata from registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub ecosystem: Ecosystem,
    pub latest_version: String,
    pub versions: Vec<String>,
}

/// Result of a package check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub latest_version: Option<String>,
    pub known_vulnerabilities_found: bool,
    pub safe_to_use: bool,
    pub risk_score: u8,
    pub recommendation: Recommendation,
    pub reason: String,
    pub summary: String,
    pub vulnerability_count: usize,
    pub highest_severity: Option<Severity>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub checked_at: String,
}

/// Comparison result between two versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareResult {
    pub ecosystem: String,
    pub package: String,
    pub from_version: String,
    pub to_version: String,
    pub from_risk_score: u8,
    pub to_risk_score: u8,
    pub risk_improved: bool,
    pub recommendation: Recommendation,
    pub next_action: String,
    pub resolved_vulnerabilities: Vec<String>,
    pub added_vulnerabilities: Vec<String>,
}
