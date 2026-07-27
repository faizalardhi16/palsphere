use clap::{Parser, Subcommand};
use palsphere::checker::Checker;
use palsphere::report::ReportGenerator;
use palsphere::types::Ecosystem;
use std::process;

#[derive(Parser)]
#[command(name = "palsphere")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Check npm and Go packages for known vulnerabilities (OSV-powered, zero auth)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check a specific package version for vulnerabilities
    Check {
        /// Ecosystem: npm or go
        ecosystem: String,
        /// Package name
        package: String,
        /// Version or "latest"
        version: String,
    },
    /// Suggest the newest safe version
    Suggest {
        /// Ecosystem: npm or go
        ecosystem: String,
        /// Package name
        package: String,
    },
    /// Compare two versions
    Compare {
        /// Ecosystem: npm or go
        ecosystem: String,
        /// Package name
        package: String,
        /// Current version
        from_version: String,
        /// Target version
        to_version: String,
    },
    /// Start MCP server (stdio)
    Mcp,
}

fn parse_ecosystem(s: &str) -> Ecosystem {
    match s.to_lowercase().as_str() {
        "npm" => Ecosystem::Npm,
        "go" => Ecosystem::Go,
        other => {
            eprintln!("Error: Unsupported ecosystem '{}'. Use 'npm' or 'go'.", other);
            process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            ecosystem,
            package,
            version,
        } => {
            let eco = parse_ecosystem(&ecosystem);
            let mut checker = Checker::new();
            match checker.check(&eco, &package, &version).await {
                Ok(result) => {
                    let icon = match result.recommendation {
                        palsphere::types::Recommendation::Allow => "🟢",
                        palsphere::types::Recommendation::Review => "🟡",
                        palsphere::types::Recommendation::Block => "🔴",
                        palsphere::types::Recommendation::Unknown => "⚪",
                    };
                    println!(
                        "{} {} {}@{}: {} vulnerabilities found",
                        icon, ecosystem, package, result.version, result.vulnerability_count
                    );
                    println!("  recommendation: {:?}", result.recommendation);
                    println!("  risk_score: {}/100", result.risk_score);

                    let report = ReportGenerator::new();
                    match report.write_check_report(&result) {
                        Ok(path) => println!("\n📄 Report: {}", path.display()),
                        Err(e) => eprintln!("Warning: Failed to save report: {}", e),
                    }

                    if result.recommendation == palsphere::types::Recommendation::Block {
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Suggest { ecosystem, package } => {
            let eco = parse_ecosystem(&ecosystem);
            let mut checker = Checker::new();
            match checker.suggest_safe_version(&eco, &package).await {
                Ok(result) => {
                    println!("{}/{}", result.package, result.version);
                    println!("  risk_score: {}/100", result.risk_score);
                    println!("  recommendation: {:?}", result.recommendation);
                    println!("\n{}", result.summary);

                    let report = ReportGenerator::new();
                    if let Ok(path) = report.write_check_report(&result) {
                        println!("\n📄 Report: {}", path.display());
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Compare {
            ecosystem,
            package,
            from_version,
            to_version,
        } => {
            let eco = parse_ecosystem(&ecosystem);
            let mut checker = Checker::new();
            match checker
                .compare_versions(&eco, &package, &from_version, &to_version)
                .await
            {
                Ok(result) => {
                    let icon = if result.risk_improved { "✅" } else { "⚠️" };
                    println!(
                        "{} {} {} → {}: risk {}/100 → {}/100",
                        icon,
                        package,
                        result.from_version,
                        result.to_version,
                        result.from_risk_score,
                        result.to_risk_score
                    );
                    println!("  recommendation: {:?}", result.recommendation);
                    println!("  next_action: {}", result.next_action);

                    if !result.resolved_vulnerabilities.is_empty() {
                        println!(
                            "  resolved: {}",
                            result.resolved_vulnerabilities.join(", ")
                        );
                    }

                    let report = ReportGenerator::new();
                    if let Ok(path) = report.write_compare_report(&result) {
                        println!("\n📄 Report: {}", path.display());
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Mcp => {
            eprintln!("🔮 palsphere MCP server starting on stdio...");
            if let Err(e) = palsphere::mcp::run_mcp_server().await {
                eprintln!("MCP server error: {}", e);
                process::exit(1);
            }
        }
    }
}
