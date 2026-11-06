use crate::{Finding, Severity};
use std::path::Path;
fn add(
    out: &mut Vec<Finding>,
    path: &Path,
    line: usize,
    id: &str,
    severity: Severity,
    confidence: f64,
    title: &str,
    detail: &str,
    fix: &str,
) {
    out.push(Finding {
        id: id.into(),
        severity,
        confidence,
        title: title.into(),
        location: format!("{}:{line}", path.display()),
        detail: detail.into(),
        remediation: fix.into(),
    });
}
pub fn inspect(path: &Path, line: usize, code: &str, out: &mut Vec<Finding>) {
    let lower = code.to_lowercase();
    // Deliberately narrow heuristics to reduce noisy matches.
    if (lower.contains("execute(") || lower.contains("query("))
        && (lower.contains("f\"")
            || lower.contains("f'")
            || lower.contains("format(")
            || lower.contains("${")
            || lower.contains("+ req.")
            || lower.contains("+ request."))
    {
        add(out,path,line,"SQL-001",Severity::High,0.65,"Possible dynamic SQL query","Query construction may include untrusted input; requires manual data-flow verification.","Use parameterized SQL queries and bound variables.");
    }
    if (lower.contains("openai") || lower.contains("messages") || lower.contains("prompt"))
        && (lower.contains("req.body")
            || lower.contains("request.args")
            || lower.contains("request.json"))
        && (lower.contains("system") || lower.contains("developer"))
    {
        add(
            out,
            path,
            line,
            "LLM-001",
            Severity::Medium,
            0.45,
            "Potential untrusted input in privileged prompt",
            "Untrusted request content appears near privileged prompt construction.",
            "Separate trusted instructions from untrusted data and validate tool actions.",
        );
    }
    if (lower.contains("api_key") || lower.contains("secret_key") || lower.contains("password"))
        && (code.contains('"') || code.contains('\''))
        && (code.contains('=') || code.contains(':'))
    {
        // Literal value check; does not report environment-variable references.
        let literal = code
            .split_once('=')
            .map(|(_, v)| v.trim())
            .or_else(|| code.split_once(':').map(|(_, v)| v.trim()))
            .unwrap_or("");
        if (literal.starts_with('"') || literal.starts_with('\'')) && literal.len() > 10 {
            add(
                out,
                path,
                line,
                "SEC-001",
                Severity::High,
                0.55,
                "Possible hard-coded credential",
                "Credential-like variable assigned a string literal.",
                "Remove the credential, rotate it if real, and use a secret manager.",
            );
        }
    }
}
