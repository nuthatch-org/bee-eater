//! Static, read-only inspection. Nothing here executes, follows a link, or reads outside the
//! folder it was pointed at.

mod formats;
mod text;

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use bee_evidence::{Evidence, Report, Severity};
use walkdir::WalkDir;

pub use text::{Context, Lang};

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILES: usize = 100_000;

const NOTHING_RAN: &str = "Nothing was run, so nothing was watched in action. bee-eater only read the files; the sandbox that runs them is not built yet.";

// Data and markup (json, toml, html, plist) are left out on purpose: a `curl | sh` in them is
// documentation. Their executable forms are read by the format-specific checks instead.
fn lang_of(name: &str, ext: &str, text: &str) -> Option<Lang> {
    let shell_names = [
        "Makefile",
        "makefile",
        "GNUmakefile",
        "Justfile",
        "justfile",
        "Rakefile",
        "Vagrantfile",
        "Taskfile",
        ".bashrc",
        ".zshrc",
        ".profile",
    ];
    if name == "Dockerfile" || name == "Containerfile" || ext == "dockerfile" {
        return Some(Lang::Container);
    }
    if shell_names.contains(&name) || text.starts_with("#!") {
        return Some(Lang::Shell);
    }
    match ext {
        "sh" | "bash" | "zsh" | "ksh" | "fish" | "command" | "tool" | "ps1" | "psm1" | "bat"
        | "cmd" | "applescript" | "yml" | "yaml" | "mk" => Some(Lang::Shell),
        "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "jsx" | "tsx" | "vue" | "svelte" | "py"
        | "rb" | "pl" | "php" | "rs" | "go" | "lua" => Some(Lang::Program),
        _ => None,
    }
}

/// Folders holding code someone else installed or built. Reading them buries the answer in
/// other people's findings; skipping them silently would hide a planted payload.
fn unread_reason(dir: &Path) -> Option<&'static str> {
    if dir.file_name().is_some_and(|n| n == "node_modules") {
        Some("installed packages (node_modules)")
    } else if dir.join("CACHEDIR.TAG").exists() {
        Some("a build cache")
    } else {
        None
    }
}

const MANIFESTS: &[&str] = &[
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "composer.json",
];

#[derive(Default)]
struct Walk {
    evidence: Vec<Evidence>,
    too_big: usize,
    compiled: Vec<(String, &'static str)>,
    symlinks: usize,
    manifests: bool,
    vscode: bool,
    unread: Vec<(String, &'static str)>,
    hit_cap: bool,
    hook_targets: Vec<String>,
}

/// Inspects a folder, or a single file, without running anything in it.
pub fn scan_path(root: &Path) -> std::io::Result<Report> {
    let meta = fs::symlink_metadata(root)?;
    let base = if meta.is_file() {
        root.parent().unwrap_or(Path::new("")).to_path_buf()
    } else {
        root.to_path_buf()
    };

    let base_abs = fs::canonicalize(&base).unwrap_or_else(|_| base.clone());
    let mut w = Walk::default();
    let walker = WalkDir::new(root).follow_links(false).sort_by_file_name();
    let mut it = walker.into_iter();
    let mut seen = 0usize;

    while let Some(entry) = it.next() {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let rel = path.strip_prefix(&base).unwrap_or(path);
        let rel_s = rel.to_string_lossy().replace('\\', "/");

        if entry.file_type().is_dir() {
            if in_git_dir(rel) && !is_git_root(rel) && !rel.ends_with("hooks") {
                it.skip_current_dir();
            }
            if let Some(reason) = unread_reason(path) {
                w.unread.push((rel_s, reason));
                it.skip_current_dir();
                continue;
            }
            if entry.file_name() == ".vscode" {
                w.vscode = true;
            }
            continue;
        }

        seen += 1;
        if seen > MAX_FILES {
            w.hit_cap = true;
            break;
        }

        if entry.path_is_symlink() {
            w.symlinks += 1;
            if let Ok(target) = fs::read_link(path)
                && escapes(rel, &target, &base_abs)
            {
                w.evidence.push(
                    Evidence::new(
                        "link-outside-folder",
                        Severity::Warning,
                        format!(
                            "A link that points outside this folder, at {}. Anything that follows it reads your files, not the folder's.",
                            target.display()
                        ),
                    )
                    .at(&rel_s, None),
                );
            }
            continue;
        }

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if size > MAX_FILE_BYTES {
            w.too_big += 1;
            continue;
        }
        let Ok(bytes) = read_capped(path) else {
            continue;
        };
        inspect_file(&mut w, rel, &rel_s, &bytes);
    }

    if let Some((first, _)) = w.unread.first() {
        let mut kinds: Vec<&str> = w.unread.iter().map(|(_, r)| *r).collect();
        kinds.sort_unstable();
        kinds.dedup();
        w.evidence.push(
            Evidence::new(
                "unread-folder",
                Severity::Opaque,
                format!(
                    "{} folder(s) of {} were not read. Code in them runs when the project does.",
                    w.unread.len(),
                    kinds.join(" and ")
                ),
            )
            .at(first, None),
        );
    }

    let targets = std::mem::take(&mut w.hook_targets);
    for target in targets {
        read_as_install_script(&mut w, &base, &target);
    }

    let mut unchecked = vec![NOTHING_RAN.to_string()];
    if w.manifests {
        unchecked.push("Its dependencies were not downloaded or checked.".into());
    }
    if w.compiled.len() > 3 {
        w.evidence.push(
            Evidence::new(
                "compiled-program",
                Severity::Opaque,
                format!(
                    "{} compiled programs, which bee-eater cannot look inside yet.",
                    w.compiled.len()
                ),
            )
            .at(&w.compiled[0].0, None),
        );
    } else {
        for (path, what) in &w.compiled {
            w.evidence.push(
                Evidence::new(
                    "compiled-program",
                    Severity::Opaque,
                    format!("A {what}. bee-eater cannot look inside compiled programs yet."),
                )
                .at(path, None),
            );
        }
    }
    if !w.compiled.is_empty() {
        unchecked.push(format!(
            "{} compiled program(s) were not looked inside.",
            w.compiled.len()
        ));
    }
    if w.vscode {
        unchecked.push("VS Code workspace settings and launch configurations were not checked, only its tasks.".into());
    }
    if w.too_big > 0 {
        unchecked.push(format!("{} file(s) over 4 MiB were skipped.", w.too_big));
    }
    if w.symlinks > 0 {
        unchecked.push(format!("{} link(s) were not followed.", w.symlinks));
    }
    if w.hit_cap {
        unchecked.push(format!(
            "The folder has more than {MAX_FILES} files; the rest were not read."
        ));
    }
    Ok(Report::build(w.evidence, unchecked))
}

/// The outcome of fetching one URL that a pasted command would download and run.
pub enum Fetch {
    Got { url: String, bytes: Vec<u8> },
    Failed { url: String, reason: String },
}

/// URLs a pasted command would download and immediately run, for the caller to fetch.
pub fn download_urls(command: &str) -> Vec<String> {
    text::download_urls(command)
}

/// Inspects a command someone is about to paste into a terminal.
pub fn scan_command(command: &str) -> Report {
    scan_command_fetched(command, &[])
}

/// As [`scan_command`], with the scripts it downloads already fetched and read in its place.
/// Nothing fetched is run or written to disk.
pub fn scan_command_fetched(command: &str, fetched: &[Fetch]) -> Report {
    let mut evidence = text::scan_text(command, Context::Pasted, "", None);
    for e in &mut evidence {
        e.location = None;
    }
    let mut unchecked = vec!["The command was not run.".to_string()];

    let wanted = text::download_urls(command);
    let got = |u: &str| {
        fetched
            .iter()
            .any(|f| matches!(f, Fetch::Got { url, .. } if url == u))
    };
    let all_read = !wanted.is_empty() && wanted.iter().all(|u| got(u));
    if all_read {
        for e in evidence.iter_mut().filter(|e| e.rule == "download-and-run") {
            e.severity = Severity::Info;
            e.summary = "Downloads a script and runs it straight away. bee-eater fetched that script and read it; what it found is listed here.".into();
        }
    }

    for f in fetched {
        match f {
            Fetch::Got { url, bytes } => {
                evidence.extend(scan_fetched(bytes, url));
                unchecked.push(format!(
                    "The script from {url} was read, not run. Anything it downloads in turn was not fetched."
                ));
            }
            Fetch::Failed { url, reason } => {
                unchecked.push(format!(
                    "Fetching {url} failed ({reason}), so it was not read."
                ));
            }
        }
    }
    for u in wanted
        .iter()
        .filter(|u| !fetched.iter().any(|f| fetch_url(f) == u.as_str()))
    {
        unchecked.push(format!(
            "The script it downloads from {u} was not fetched or read. `issafe --fetch` reads it without running it."
        ));
    }
    if wanted.is_empty() && text::has_download_exec(command) {
        unchecked.push("The script it downloads was not fetched or read; bee-eater could not pick out its address.".into());
    }
    Report::build(evidence, unchecked)
}

fn fetch_url(f: &Fetch) -> &str {
    match f {
        Fetch::Got { url, .. } | Fetch::Failed { url, .. } => url,
    }
}

fn scan_fetched(bytes: &[u8], url: &str) -> Vec<Evidence> {
    if let formats::Magic::Compiled(what) = formats::magic_of(bytes) {
        return vec![
            Evidence::new(
                "compiled-program",
                Severity::Opaque,
                format!("What it downloads is a {what}, not a script, and bee-eater cannot look inside it yet."),
            )
            .at(url, None),
        ];
    }
    let Some(text) = as_text(bytes) else {
        return vec![
            Evidence::new(
                "unreadable-download",
                Severity::Opaque,
                "What it downloads is neither a script nor anything bee-eater can read.",
            )
            .at(url, None),
        ];
    };
    let head = text
        .trim_start()
        .get(..64)
        .unwrap_or(text.trim_start())
        .to_ascii_lowercase();
    if head.starts_with("<!doctype html") || head.starts_with("<html") {
        return vec![
            Evidence::new(
                "unreadable-download",
                Severity::Opaque,
                "The address answered with a web page, not a script. Lure servers show a harmless page to anything they think is a scanner.",
            )
            .at(url, None),
        ];
    }
    let mut found = text::scan_text(text, Context::Fetched, url, Some(0));
    let unseen_stage = found
        .iter()
        .any(|e| e.rule == "download-and-run" && e.severity >= Severity::Opaque);
    if !unseen_stage && let Some((line, tool, excerpt)) = text::fetch_tool(text) {
        found.push(
            Evidence::new(
                "downloads-more",
                Severity::Opaque,
                format!(
                    "This script can download more (it uses {tool}), and whatever it downloads was not fetched or read. Installers often do the real work in that second download."
                ),
            )
            .at(url, Some(line))
            .excerpt(excerpt),
        );
    }
    found
}

fn inspect_file(w: &mut Walk, rel: &Path, rel_s: &str, bytes: &[u8]) {
    let name = rel
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = rel
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let parent = rel
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let text = as_text(bytes);

    if MANIFESTS.contains(&name.as_str()) {
        w.manifests = true;
    }

    if let Some(kind) = formats::media_kind(&ext) {
        w.evidence
            .extend(formats::disguised_media(bytes, text, kind, rel_s));
        // Once unmasked it is code with no honest language, so every line counts.
        if let Some(t) = text {
            w.evidence.extend(text::scan_text(
                t,
                Context::Code(Lang::Shell),
                rel_s,
                Some(0),
            ));
        }
        return;
    }
    if let formats::Magic::Compiled(what) = formats::magic_of(bytes) {
        w.compiled.push((rel_s.to_string(), what));
        return;
    }
    let Some(text) = text else { return };

    if in_git_dir(rel) {
        if name == "config" && parent == ".git" {
            w.evidence.extend(formats::git_config(text, rel_s));
        } else if parent == "hooks" && !name.ends_with(".sample") {
            w.evidence.push(
                Evidence::new(
                    "git-hook",
                    Severity::Warning,
                    "A git hook, which runs by itself on commits, checkouts or merges in this folder.",
                )
                .at(rel_s, None),
            );
            w.evidence
                .extend(text::scan_text(text, Context::AutoRun, rel_s, Some(0)));
        }
        return;
    }

    if name == "tasks.json" && matches!(parent.as_str(), ".vscode" | ".cursor" | ".windsurf")
        || ext == "code-workspace"
    {
        w.evidence.extend(formats::editor_tasks(text, rel_s));
        return;
    }

    if name == "package.json" {
        w.evidence.extend(formats::package_json(text, rel_s));
        let dir = rel.parent().unwrap_or(Path::new(""));
        for script in formats::hook_scripts(text) {
            if let Some(target) = join_inside(dir, &script) {
                w.hook_targets
                    .push(target.to_string_lossy().replace('\\', "/"));
            }
        }
    }

    let auto_run = match name.as_str() {
        "setup.py" => Some("pip runs this file as a program during install."),
        "build.rs" => Some("Cargo runs this file as a program during every build."),
        ".envrc" => {
            Some("direnv runs this file when you enter the folder, if you have allowed it.")
        }
        _ if parent == ".husky" => {
            Some("Husky installs this as a git hook, which runs by itself on commits.")
        }
        _ => None,
    };
    if let Some(summary) = auto_run {
        w.evidence
            .push(Evidence::new("runs-on-install", Severity::Info, summary).at(rel_s, None));
        w.evidence
            .extend(text::scan_text(text, Context::AutoRun, rel_s, Some(0)));
        return;
    }

    if name == "pyproject.toml" && text.contains("backend-path") {
        w.evidence.push(
            Evidence::new(
                "runs-on-install",
                Severity::Info,
                "pip runs a build program from inside this folder during install.",
            )
            .at(rel_s, None),
        );
    }

    if ext == "pth"
        && let Some((n, line)) = text
            .lines()
            .enumerate()
            .find(|(_, l)| l.starts_with("import ") || l.starts_with("import\t"))
    {
        w.evidence.push(
            Evidence::new(
                "python-startup-hook",
                Severity::Warning,
                "Python runs this line every time it starts, in every program, once the package is installed.",
            )
            .at(rel_s, Some(n + 1))
            .excerpt(line),
        );
    }

    if ext == "svg" && text.to_ascii_lowercase().contains("<script") {
        w.evidence.push(
            Evidence::new(
                "script-in-image",
                Severity::Warning,
                "An image file that carries a script.",
            )
            .at(rel_s, None),
        );
    }

    if let Some(lang) = lang_of(&name, &ext, text) {
        w.evidence
            .extend(text::scan_text(text, Context::Code(lang), rel_s, Some(0)));
    }
}

/// A file an install hook runs is auto-run code, so it is read again at that weight and its
/// ordinary-code findings are replaced.
fn read_as_install_script(w: &mut Walk, base: &Path, rel_s: &str) {
    let path = base.join(rel_s);
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return;
    };
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return;
    }
    let Ok(bytes) = read_capped(&path) else {
        return;
    };
    let Some(text) = as_text(&bytes) else {
        return;
    };
    w.evidence.retain(|e| {
        e.location.as_ref().is_none_or(|l| l.path != rel_s)
            || !matches!(e.severity, Severity::Warning | Severity::Info)
    });
    w.evidence
        .extend(text::scan_text(text, Context::AutoRun, rel_s, Some(0)));
    if let Some((line, tool, excerpt)) = text::fetch_tool(text) {
        w.evidence.push(
            Evidence::new(
                "downloads-more",
                Severity::Opaque,
                format!(
                    "npm runs this file during install, and it can download more (it uses {tool}). Whatever it downloads was not fetched or read."
                ),
            )
            .at(rel_s, Some(line))
            .excerpt(excerpt),
        );
    }
}

fn join_inside(dir: &Path, rel: &str) -> Option<PathBuf> {
    let mut out = dir.to_path_buf();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    fs::File::open(path)?
        .take(MAX_FILE_BYTES)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

fn as_text(bytes: &[u8]) -> Option<&str> {
    let head = &bytes[..bytes.len().min(8192)];
    if head.contains(&0) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

fn in_git_dir(rel: &Path) -> bool {
    rel.components().any(|c| c.as_os_str() == ".git")
}

fn is_git_root(rel: &Path) -> bool {
    rel.file_name().is_some_and(|n| n == ".git")
}

/// Lexical, never resolved: resolving would touch whatever the link points at.
fn escapes(link: &Path, target: &Path, root_abs: &Path) -> bool {
    let (target, mut depth) = if target.is_absolute() {
        match target.strip_prefix(root_abs) {
            Ok(inside) => (inside, 0isize),
            Err(_) => return true,
        }
    } else {
        let depth = link
            .parent()
            .map(|p| p.components().count() as isize)
            .unwrap_or(0);
        (target, depth)
    };
    for c in target.components() {
        match c {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            _ => {}
        }
        if depth < 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_links_that_climb_out() {
        let root = Path::new("/work/repo");
        assert!(escapes(
            Path::new("a/link"),
            Path::new("../../etc/passwd"),
            root
        ));
        assert!(!escapes(Path::new("a/link"), Path::new("../b/file"), root));
        assert!(escapes(
            Path::new("link"),
            Path::new("/Users/someone/.ssh"),
            root
        ));
        assert!(!escapes(
            Path::new("link"),
            Path::new("/work/repo/tmp/x"),
            root
        ));
        assert!(escapes(
            Path::new("link"),
            Path::new("/work/repo/../other"),
            root
        ));
    }
}
