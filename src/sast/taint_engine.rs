use crate::Finding;
use std::path::Path;
use tree_sitter::{Language, Parser};
fn language(ext: &str) -> Option<Language> {
    Some(match ext {
        "py" => tree_sitter_python::LANGUAGE.into(),
        "js" | "jsx" => tree_sitter_javascript::LANGUAGE.into(),
        "ts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "cpp" | "cc" | "cxx" | "hpp" | "h" => tree_sitter_cpp::LANGUAGE.into(),
        _ => return None,
    })
}
pub fn analyze(path: &Path, source: &str) -> (Vec<Finding>, bool) {
    let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
    let Some(lang) = language(ext) else {
        return (vec![], false);
    };
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return (vec![], true);
    }
    let Some(tree) = parser.parse(source, None) else {
        return (vec![], true);
    };
    let mut findings = vec![];
    // Only inspect named AST nodes. This is AST-assisted pattern matching,
    // NOT interprocedural taint tracking or proof of exploitability.
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_named()
            && matches!(
                node.kind(),
                "call"
                    | "call_expression"
                    | "assignment"
                    | "variable_declarator"
                    | "lexical_declaration"
                    | "expression_statement"
            )
        {
            if let Ok(code) = node.utf8_text(source.as_bytes()) {
                crate::sast::rules::inspect(
                    path,
                    node.start_position().row + 1,
                    code,
                    &mut findings,
                );
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    findings.sort_by(|a, b| a.location.cmp(&b.location).then(a.id.cmp(&b.id)));
    findings.dedup_by(|a, b| a.location == b.location && a.id == b.id);
    (findings, tree.root_node().has_error())
}
