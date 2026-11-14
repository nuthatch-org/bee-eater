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
            "1",
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

    let notes = read_bare(&bare, &out)?;
    Ok(Unpacked {
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
}
