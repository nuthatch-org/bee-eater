//! Package specs: fetch one published version from its registry, check it against the
//! registry's own hash, and unpack it as inert files for the static scan. Nothing is installed.

use std::fs;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use flate2::read::GzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

use crate::fetch::fetch_bytes;

const META_MAX: u64 = 4 * 1024 * 1024;
const ARCHIVE_MAX: u64 = 50 * 1024 * 1024;
const UNPACKED_MAX: u64 = 200 * 1024 * 1024;
const ENTRIES_MAX: usize = 50_000;

#[derive(Debug, PartialEq, Eq)]
pub enum Spec {
    Npm {
        name: String,
        version: String,
    },
    Pypi {
        name: String,
        version: Option<String>,
    },
}

impl Spec {
    pub fn parse(input: &str) -> Option<Result<Spec, String>> {
        if let Some(rest) = input.strip_prefix("npm:") {
            let (name, version) = match rest.get(1..).and_then(|s| s.rfind('@')) {
                Some(i) => (&rest[..i + 1], &rest[i + 2..]),
                None => (rest, "latest"),
            };
            return Some(valid_npm(name).map(|()| Spec::Npm {
                name: name.to_string(),
                version: version.to_string(),
            }));
        }
        if let Some(rest) = input
            .strip_prefix("pypi:")
            .or_else(|| input.strip_prefix("pip:"))
        {
            let (name, version) = match rest.split_once("==").or_else(|| rest.split_once('@')) {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (rest, None),
            };
            return Some(valid_pypi(name).map(|()| Spec::Pypi {
                name: name.to_string(),
                version,
            }));
        }
        None
    }
}

fn valid_npm(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 214
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~@/".contains(c))
        && name.matches('/').count() <= usize::from(name.starts_with('@'));
    ok.then_some(())
        .ok_or_else(|| format!("{name:?} is not an npm package name"))
}

fn valid_pypi(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 200
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._".contains(c));
    ok.then_some(())
        .ok_or_else(|| format!("{name:?} is not a PyPI package name"))
}

pub struct Unpacked {
    /// The folder to scan; the temp dir is removed when this is dropped.
    pub root: PathBuf,
    pub label: String,
    pub notes: Vec<String>,
    pub(crate) _dir: tempfile::TempDir,
}

pub fn fetch_and_unpack(spec: &Spec) -> Result<Unpacked, String> {
    let dir = tempfile::Builder::new()
        .prefix("bee-eater-pkg-")
        .tempdir()
        .map_err(|e| format!("could not make a scratch folder: {e}"))?;
    match spec {
        Spec::Npm { name, version } => npm(name, version, dir),
        Spec::Pypi { name, version } => pypi(name, version.as_deref(), dir),
    }
}

fn json(url: &str) -> Result<Value, String> {
    let bytes = fetch_bytes(url, META_MAX).map_err(|e| {
        if e.contains("404") {
            "the registry has no such package or version".to_string()
        } else {
            e
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|_| format!("{url} did not answer with JSON"))
}

fn npm(name: &str, version: &str, dir: tempfile::TempDir) -> Result<Unpacked, String> {
    let path_name = name.replacen('/', "%2f", 1);
    let meta = json(&format!("https://registry.npmjs.org/{path_name}/{version}"))?;
    let resolved = meta["version"]
        .as_str()
        .ok_or("the registry has no such version")?;
    let tarball = meta["dist"]["tarball"]
        .as_str()
        .ok_or("the registry gave no tarball")?;
    let integrity = meta["dist"]["integrity"].as_str();

    let bytes = fetch_bytes(tarball, ARCHIVE_MAX)?;
    match integrity.and_then(|i| i.strip_prefix("sha512-")) {
        Some(expected) => {
            let got = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes));
            if got != expected {
                return Err("the tarball does not match the registry's sha512".into());
            }
        }
        None => return Err("the registry gave no sha512 to check the tarball against".into()),
    }

    let mut notes = Vec::new();
    unpack_tar_gz(&bytes, dir.path(), &mut notes)?;
    // npm tarballs keep everything under `package/`, which is what npm installs.
    let root = if dir.path().join("package").is_dir() {
        dir.path().join("package")
    } else {
        dir.path().to_path_buf()
    };
    Ok(Unpacked {
        root,
        label: format!("npm:{name}@{resolved}"),
        notes,
        _dir: dir,
    })
}

fn pypi(name: &str, version: Option<&str>, dir: tempfile::TempDir) -> Result<Unpacked, String> {
    let url = match version {
        Some(v) => format!("https://pypi.org/pypi/{name}/{v}/json"),
        None => format!("https://pypi.org/pypi/{name}/json"),
    };
    let meta = json(&url)?;
    let resolved = meta["info"]["version"]
        .as_str()
        .ok_or("PyPI has no such version")?;
    let files = meta["urls"].as_array().ok_or("PyPI listed no files")?;
    // The sdist is what runs code at install time, so it is the one worth reading.
    let pick = files
        .iter()
        .find(|f| f["packagetype"] == "sdist")
        .or_else(|| files.iter().find(|f| f["packagetype"] == "bdist_wheel"))
        .ok_or("PyPI listed neither a source archive nor a wheel")?;
    let file_url = pick["url"]
        .as_str()
        .ok_or("PyPI gave no download address")?;
    let filename = pick["filename"].as_str().unwrap_or("");
    let expected = pick["digests"]["sha256"]
        .as_str()
        .ok_or("PyPI gave no sha256")?;

    let bytes = fetch_bytes(file_url, ARCHIVE_MAX)?;
    let got: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != expected {
        return Err("the download does not match PyPI's sha256".into());
    }

    let mut notes = Vec::new();
    if filename.ends_with(".whl") || filename.ends_with(".zip") {
        unpack_zip(&bytes, dir.path(), &mut notes)?;
        if pick["packagetype"] == "bdist_wheel" {
            notes.push(
                "Only a wheel was published; it was read instead of the source archive.".into(),
            );
        }
    } else if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        unpack_tar_gz(&bytes, dir.path(), &mut notes)?;
    } else {
        return Err(format!("{filename} is not an archive bee-eater can open"));
    }
    if files.len() > 1 {
        notes.push(format!(
            "{} other file(s) of this release, such as wheels for other platforms, were not read.",
            files.len() - 1
        ));
    }
    Ok(Unpacked {
        root: dir.path().to_path_buf(),
        label: format!("pypi:{name}=={resolved}"),
        notes,
        _dir: dir,
    })
}

/// Only plain relative paths survive: no `..`, no root, no drive prefix.
pub(crate) fn safe_rel(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

pub(crate) struct Budget {
    bytes: u64,
    entries: usize,
    pub(crate) skipped_links: usize,
    pub(crate) skipped_paths: usize,
}

impl Budget {
    pub(crate) fn new() -> Self {
        Budget {
            bytes: 0,
            entries: 0,
            skipped_links: 0,
            skipped_paths: 0,
        }
    }

    pub(crate) fn take(&mut self, size: u64) -> Result<(), String> {
        self.entries += 1;
        self.bytes += size;
        if self.entries > ENTRIES_MAX || self.bytes > UNPACKED_MAX {
            return Err("the archive unpacks to more than bee-eater will read".into());
        }
        Ok(())
    }

    pub(crate) fn notes(&self, notes: &mut Vec<String>) {
        if self.skipped_links > 0 {
            notes.push(format!(
                "{} link(s) inside the archive were not unpacked.",
                self.skipped_links
            ));
        }
        if self.skipped_paths > 0 {
            notes.push(format!(
                "{} archive entr(ies) tried to write outside the package folder and were refused.",
                self.skipped_paths
            ));
        }
    }
}

pub(crate) fn write_inert(root: &Path, rel: &Path, data: &[u8]) -> Result<(), String> {
    let dest = root.join(rel);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&dest, data).map_err(|e| e.to_string())
}

fn unpack_tar_gz(bytes: &[u8], root: &Path, notes: &mut Vec<String>) -> Result<(), String> {
    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(bytes)));
    let mut budget = Budget::new();
    let entries = archive
        .entries()
        .map_err(|_| "not a readable tar.gz archive")?;
    for entry in entries {
        let mut entry = entry.map_err(|_| "a damaged archive entry")?;
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            budget.skipped_links += 1;
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        let Some(rel) = entry.path().ok().and_then(|p| safe_rel(&p)) else {
            budget.skipped_paths += 1;
            continue;
        };
        budget.take(entry.size())?;
        let mut data = Vec::new();
        (&mut entry)
            .take(UNPACKED_MAX)
            .read_to_end(&mut data)
            .map_err(|_| "a damaged archive entry")?;
        write_inert(root, &rel, &data)?;
    }
    budget.notes(notes);
    Ok(())
}

fn unpack_zip(bytes: &[u8], root: &Path, notes: &mut Vec<String>) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| "not a readable zip")?;
    let mut budget = Budget::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|_| "a damaged zip entry")?;
        if file.is_symlink() {
            budget.skipped_links += 1;
            continue;
        }
        if file.is_dir() {
            continue;
        }
        let Some(rel) = file.enclosed_name().and_then(|p| safe_rel(&p)) else {
            budget.skipped_paths += 1;
            continue;
        };
        budget.take(file.size())?;
        let mut data = Vec::new();
        (&mut file)
            .take(UNPACKED_MAX)
            .read_to_end(&mut data)
            .map_err(|_| "a damaged zip entry")?;
        write_inert(root, &rel, &data)?;
    }
    budget.notes(notes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs() {
        let npm = |n: &str, v: &str| {
            Some(Ok(Spec::Npm {
                name: n.into(),
                version: v.into(),
            }))
        };
        assert_eq!(Spec::parse("npm:left-pad@1.3.0"), npm("left-pad", "1.3.0"));
        assert_eq!(Spec::parse("npm:left-pad"), npm("left-pad", "latest"));
        assert_eq!(
            Spec::parse("npm:@types/node@20.1.0"),
            npm("@types/node", "20.1.0")
        );
        assert_eq!(Spec::parse("npm:@types/node"), npm("@types/node", "latest"));
        assert!(matches!(Spec::parse("npm:../../etc"), Some(Err(_))));
        assert!(matches!(Spec::parse("npm:a/b"), Some(Err(_))));
        assert!(matches!(Spec::parse("npm:"), Some(Err(_))));
        assert_eq!(
            Spec::parse("pypi:requests==2.32.3"),
            Some(Ok(Spec::Pypi {
                name: "requests".into(),
                version: Some("2.32.3".into())
            }))
        );
        assert!(matches!(Spec::parse("pypi:a/b"), Some(Err(_))));
        assert_eq!(Spec::parse("./folder"), None);
    }

    #[test]
    fn archive_paths_cannot_escape() {
        assert_eq!(
            safe_rel(Path::new("package/index.js")),
            Some(PathBuf::from("package/index.js"))
        );
        assert_eq!(
            safe_rel(Path::new("./package/a")),
            Some(PathBuf::from("package/a"))
        );
        assert_eq!(safe_rel(Path::new("../evil")), None);
        assert_eq!(safe_rel(Path::new("package/../../evil")), None);
        assert_eq!(safe_rel(Path::new("/etc/passwd")), None);
    }

    #[test]
    fn tar_with_traversal_and_links_is_unpacked_safely() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut add = |path: &str, body: &[u8]| {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Regular);
            // set_path refuses `..`, so the raw name is written to model a hostile archive.
            h.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
            h.set_cksum();
            builder.append(&h, body).unwrap();
        };
        add("package/index.js", b"module.exports = 1\n");
        add("../escaped.txt", b"x");
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        builder
            .append_link(&mut link, "package/key", "/Users/someone/.ssh/id_ed25519")
            .unwrap();
        let raw = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &raw).unwrap();
        let bytes = gz.finish().unwrap();

        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("root");
        fs::create_dir(&root).unwrap();
        let mut notes = Vec::new();
        unpack_tar_gz(&bytes, &root, &mut notes).unwrap();

        assert!(root.join("package/index.js").is_file());
        assert!(!outer.path().join("escaped.txt").exists());
        assert!(!root.join("package/key").exists());
        assert!(notes.iter().any(|n| n.contains("link")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("outside")), "{notes:?}");
    }
}
