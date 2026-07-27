use crate::checker::Checker;
use crate::types::Ecosystem;
use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use std::io::{self, BufRead, Write};

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, serde::Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, serde::Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Debug, serde::Serialize)]
struct InitializeResult {
    protocol_version: String,
    server_info: ServerInfo,
    capabilities: ServerCapabilities,
}

#[derive(Debug, serde::Serialize)]
struct ServerInfo {
    name: String,
    version: String,
}

#[derive(Debug, serde::Serialize)]
struct ServerCapabilities {
    tools: ToolsCapability,
}

#[derive(Debug, serde::Serialize)]
struct ToolsCapability {}

#[derive(Debug, serde::Serialize)]
struct Tool {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
}

#[derive(Debug, serde::Serialize)]
struct ToolCallResult {
    content: Vec<ToolContent>,
    #[serde(rename = "isError")]
    is_error: bool,
}

#[derive(Debug, serde::Serialize)]
struct ToolContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

pub async fn run_mcp_server() -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();

    let mut checker = Checker::new();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let error_response = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                    }),
                };
                let mut out = stdout.lock();
                let _ = writeln!(out, "{}", serde_json::to_string(&error_response).unwrap());
                let _ = out.flush();
                continue;
            }
        };

        // Skip notifications (no id field)
        if request.id.is_none() && request.method != "initialize" {
            continue;
        }

        let response = handle_request(&request, &mut checker).await;
        if response.id.is_some() || request.method == "initialize" {
            let mut out = stdout.lock();
            let _ = writeln!(out, "{}", serde_json::to_string(&response).unwrap());
            let _ = out.flush();
        }
    }

    Ok(())
}

async fn handle_request(request: &JsonRpcRequest, checker: &mut Checker) -> JsonRpcResponse {
    match request.method.as_str() {
        "initialize" => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id.clone(),
            result: Some(
                serde_json::to_value(InitializeResult {
                    protocol_version: "2024-11-05".to_string(),
                    server_info: ServerInfo {
                        name: "palsphere".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    },
                    capabilities: ServerCapabilities {
                        tools: ToolsCapability {},
                    },
                })
                .unwrap(),
            ),
            error: None,
        },
        "notifications/initialized" => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: None,
            result: None,
            error: None,
        },
        "tools/list" => {
            let tools = vec![
                Tool {
                    name: "check_package".to_string(),
                    description: "Check a package version for known vulnerabilities".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "ecosystem": {"type": "string", "enum": ["npm", "go"], "description": "Package ecosystem"},
                            "package": {"type": "string", "description": "Package name"},
                            "version": {"type": "string", "description": "Version to check, or 'latest'"}
                        },
                        "required": ["ecosystem", "package", "version"]
                    }),
                },
                Tool {
                    name: "suggest_safe_version".to_string(),
                    description: "Find the newest safely installable version".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "ecosystem": {"type": "string", "enum": ["npm", "go"], "description": "Package ecosystem"},
                            "package": {"type": "string", "description": "Package name"}
                        },
                        "required": ["ecosystem", "package"]
                    }),
                },
                Tool {
                    name: "compare_versions".to_string(),
                    description: "Compare two versions for vulnerability risk".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "ecosystem": {"type": "string", "enum": ["npm", "go"], "description": "Package ecosystem"},
                            "package": {"type": "string", "description": "Package name"},
                            "from_version": {"type": "string", "description": "Current version"},
                            "to_version": {"type": "string", "description": "Target version"}
                        },
                        "required": ["ecosystem", "package", "from_version", "to_version"]
                    }),
                },
            ];
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id.clone(),
                result: Some(serde_json::to_value(tools).unwrap()),
                error: None,
            }
        }
        "tools/call" => {
            let params = request.params.as_ref().and_then(|p| p.as_object());
            let tool_name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
            let arguments = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null);

            match tool_name {
                "check_package" => {
                    let eco_str = arguments.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("");
                    let pkg = arguments.get("package").and_then(|v| v.as_str()).unwrap_or("");
                    let ver = arguments.get("version").and_then(|v| v.as_str()).unwrap_or("latest");

                    let ecosystem = match eco_str.to_lowercase().as_str() {
                        "npm" => Ecosystem::Npm,
                        "go" => Ecosystem::Go,
                        _ => return err_resp(request.id.clone(), -32602, format!("Invalid ecosystem: {}", eco_str)),
                    };

                    match checker.check(&ecosystem, pkg, ver).await {
                        Ok(result) => tool_success(request.id.clone(), &serde_json::json!({
                            "ecosystem": result.ecosystem,
                            "package": result.package,
                            "version": result.version,
                            "known_vulnerabilities_found": result.known_vulnerabilities_found,
                            "safe_to_use": result.safe_to_use,
                            "risk_score": result.risk_score,
                            "recommendation": format!("{:?}", result.recommendation),
                            "reason": result.reason,
                            "summary": result.summary,
                            "vulnerability_count": result.vulnerability_count,
                            "highest_severity": result.highest_severity.map(|s| s.to_string()),
                            "vulnerabilities": result.vulnerabilities.iter().map(|v| serde_json::json!({
                                "id": v.id,
                                "summary": v.summary,
                                "severity": v.severity.as_ref().map(|s| s.to_string()),
                                "fixed_versions": v.fixed_versions,
                            })).collect::<Vec<_>>(),
                            "full_response_command": format!("palsphere check {} {} {}", result.ecosystem, result.package, result.version),
                        })),
                        Err(e) => err_resp(request.id.clone(), -32000, format!("Check failed: {}", e)),
                    }
                }
                "suggest_safe_version" => {
                    let eco_str = arguments.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("");
                    let pkg = arguments.get("package").and_then(|v| v.as_str()).unwrap_or("");
                    let ecosystem = match eco_str.to_lowercase().as_str() {
                        "npm" => Ecosystem::Npm,
                        "go" => Ecosystem::Go,
                        _ => return err_resp(request.id.clone(), -32602, format!("Invalid ecosystem: {}", eco_str)),
                    };
                    match checker.suggest_safe_version(&ecosystem, pkg).await {
                        Ok(result) => tool_success(request.id.clone(), &serde_json::json!({
                            "package": result.package,
                            "version": result.version,
                            "safe_to_use": result.safe_to_use,
                            "risk_score": result.risk_score,
                            "recommendation": format!("{:?}", result.recommendation),
                            "summary": result.summary,
                        })),
                        Err(e) => err_resp(request.id.clone(), -32000, format!("Suggest failed: {}", e)),
                    }
                }
                "compare_versions" => {
                    let eco_str = arguments.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("");
                    let pkg = arguments.get("package").and_then(|v| v.as_str()).unwrap_or("");
                    let from = arguments.get("from_version").and_then(|v| v.as_str()).unwrap_or("");
                    let to = arguments.get("to_version").and_then(|v| v.as_str()).unwrap_or("");
                    let ecosystem = match eco_str.to_lowercase().as_str() {
                        "npm" => Ecosystem::Npm,
                        "go" => Ecosystem::Go,
                        _ => return err_resp(request.id.clone(), -32602, format!("Invalid ecosystem: {}", eco_str)),
                    };
                    match checker.compare_versions(&ecosystem, pkg, from, to).await {
                        Ok(result) => tool_success(request.id.clone(), &serde_json::json!({
                            "from_version": result.from_version,
                            "to_version": result.to_version,
                            "from_risk_score": result.from_risk_score,
                            "to_risk_score": result.to_risk_score,
                            "risk_improved": result.risk_improved,
                            "recommendation": format!("{:?}", result.recommendation),
                            "next_action": result.next_action,
                            "resolved": result.resolved_vulnerabilities,
                            "added": result.added_vulnerabilities,
                        })),
                        Err(e) => err_resp(request.id.clone(), -32000, format!("Compare failed: {}", e)),
                    }
                }
                unknown => err_resp(request.id.clone(), -32601, format!("Unknown tool: {}", unknown)),
            }
        }
        "ping" => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id.clone(),
            result: Some(serde_json::json!({})),
            error: None,
        },
        _ => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id.clone(),
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", request.method),
            }),
        },
    }
}

fn tool_success(id: Option<Value>, result: &Value) -> JsonRpcResponse {
    let tool_result = ToolCallResult {
        content: vec![ToolContent {
            content_type: "text".to_string(),
            text: serde_json::to_string_pretty(result).unwrap_or_default(),
        }],
        is_error: false,
    };
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(serde_json::to_value(tool_result).unwrap()),
        error: None,
    }
}

fn err_resp(id: Option<Value>, code: i32, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(JsonRpcError { code, message }),
    }
}
