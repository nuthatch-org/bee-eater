use std::io::Write;
use std::path::Path;

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    pub fix: Option<String>,
}

fn first_existing(paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|p| p.to_string())
}

fn library(name: &'static str, paths: &[&str], fix: &str) -> Check {
    match first_existing(paths) {
        Some(p) => Check {
            name,
            ok: true,
            detail: p,
            fix: None,
        },
        None => Check {
            name,
            ok: false,
            detail: "not found".into(),
            fix: Some(fix.into()),
        },
    }
}

#[cfg(target_os = "macos")]
fn platform_checks() -> Vec<Check> {
    let arm = std::env::consts::ARCH == "aarch64";
    let hv = std::process::Command::new("sysctl")
        .args(["-n", "kern.hv_support"])
        .output()
        .ok()
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "1");
    let brew_fix = "brew tap slp/krun && brew trust slp/krun && brew install libkrun";
    vec![
        Check {
            name: "Apple Silicon",
            ok: arm,
            detail: std::env::consts::ARCH.into(),
            fix: (!arm).then(|| {
                "The sandbox needs Apple Silicon; on an Intel Mac only the static check works."
                    .into()
            }),
        },
        Check {
            name: "Hypervisor.framework",
            ok: hv,
            detail: if hv { "available" } else { "unavailable" }.into(),
            fix: (!hv).then(|| {
                "This Mac reports no hypervisor support, which usually means it is itself a virtual machine."
                    .into()
            }),
        },
        library(
            "libkrun",
            &["/opt/homebrew/lib/libkrun.dylib", "/usr/local/lib/libkrun.dylib"],
            brew_fix,
        ),
        library(
            "libkrunfw (guest kernel)",
            &["/opt/homebrew/lib/libkrunfw.dylib", "/usr/local/lib/libkrunfw.dylib"],
            brew_fix,
        ),
    ]
}

#[cfg(target_os = "linux")]
fn platform_checks() -> Vec<Check> {
    let kvm = Path::new("/dev/kvm");
    let present = kvm.exists();
    let usable = present
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(kvm)
            .is_ok();
    let pkg_fix = "Install libkrun and libkrunfw from your distribution (Fedora: dnf install libkrun) or build them from github.com/containers/libkrun.";
    vec![
        Check {
            name: "/dev/kvm",
            ok: usable,
            detail: match (present, usable) {
                (false, _) => "missing".into(),
                (true, false) => "present but not usable by this user".into(),
                (true, true) => "usable".into(),
            },
            fix: match (present, usable) {
                (false, _) => Some("Enable virtualisation in the firmware, or nested virtualisation if this is a cloud VM.".into()),
                (true, false) => Some("sudo usermod -aG kvm \"$USER\", then log out and back in.".into()),
                (true, true) => None,
            },
        },
        library(
            "libkrun",
            &[
                "/usr/lib64/libkrun.so.1",
                "/usr/lib/libkrun.so.1",
                "/usr/local/lib64/libkrun.so.1",
                "/usr/local/lib/libkrun.so.1",
                "/usr/lib/x86_64-linux-gnu/libkrun.so.1",
                "/usr/lib/aarch64-linux-gnu/libkrun.so.1",
            ],
            pkg_fix,
        ),
        library(
            "libkrunfw (guest kernel)",
            &[
                "/usr/lib64/libkrunfw.so.5",
                "/usr/lib/libkrunfw.so.5",
                "/usr/local/lib64/libkrunfw.so.5",
                "/usr/local/lib/libkrunfw.so.5",
                "/usr/lib/x86_64-linux-gnu/libkrunfw.so.5",
                "/usr/lib/aarch64-linux-gnu/libkrunfw.so.5",
            ],
            pkg_fix,
        ),
    ]
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_checks() -> Vec<Check> {
    vec![Check {
        name: "platform",
        ok: false,
        detail: std::env::consts::OS.into(),
        fix: Some("The sandbox is planned for macOS and Linux only.".into()),
    }]
}

/// Returns whether everything the sandbox needs is present.
pub fn run(out: &mut impl Write) -> std::io::Result<bool> {
    let checks = platform_checks();
    writeln!(out, "Static check (reading files and commands): ready")?;
    writeln!(out, "\nSandbox (running things in a disposable VM):")?;
    for c in &checks {
        let mark = if c.ok { "ok     " } else { "missing" };
        writeln!(out, "  {mark}  {:<26} {}", c.name, c.detail)?;
        if let Some(fix) = &c.fix {
            writeln!(out, "           fix: {fix}")?;
        }
    }
    let ready = checks.iter().all(|c| c.ok);
    writeln!(
        out,
        "\n{}",
        if ready {
            "This machine has what the sandbox needs. The sandbox itself is not built yet."
        } else {
            "The sandbox would not run here yet; the static check is unaffected."
        }
    )?;
    Ok(ready)
}
