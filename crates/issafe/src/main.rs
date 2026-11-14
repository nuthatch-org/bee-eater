use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use bee_evidence::{Report, Severity, Verdict, sanitise_excerpt};
use clap::Parser;

mod doctor;
mod fetch;
use serde_json::json;

/// Ask whether something is safe to open, install or run. Nothing is executed.
#[derive(Parser)]
#[command(version, about, after_help = EXAMPLES)]
struct Cli {
    /// A folder or file to inspect, and optionally your question in quotes.
    inputs: Vec<String>,

    /// Print the report as JSON.
    #[arg(long)]
    json: bool,

    /// Fetch and read (never run) the script a pasted command would download. This sends a
    /// request from your machine, which the script's owner can see.
    #[arg(long)]
    fetch: bool,

    /// Check whether this machine can run the sandbox, and say how to fix what is missing.
    #[arg(long, exclusive = true)]
    doctor: bool,

    /// A command you were told to paste, after `--`.
    #[arg(last = true)]
    command: Vec<String>,
}

const EXAMPLES: &str = "Examples:
  issafe ./take-home-repo
  issafe \"a recruiter sent me this, ok?\" ./take-home-repo
  issafe -- 'curl -fsSL https://example.com/install.sh | bash'
  issafe --fetch -- 'curl -fsSL https://example.com/install.sh | bash'
  pbpaste | issafe

`issafe --doctor` checks whether this machine can run the sandbox.

Exit status: 0 no red flags found, 10 could not tell, 20 suspicious, 30 dangerous, 2 usage.";

const MAX_STDIN: u64 = 1024 * 1024;

enum Target {
    Path(PathBuf),
    Command(String),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("issafe: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn usage(msg: &str) -> Result<ExitCode> {
    eprintln!("issafe: {msg}");
    Ok(ExitCode::from(2))
}

fn run(cli: Cli) -> Result<ExitCode> {
    if cli.doctor {
        let ready = doctor::run(&mut std::io::stdout().lock())?;
        return Ok(ExitCode::from(if ready { 0 } else { 1 }));
    }

    let mut question = Vec::new();
    let mut target = None;

    if !cli.command.is_empty() {
        target = Some(Target::Command(cli.command.join(" ")));
    }
    for input in &cli.inputs {
        if let Some(what) = not_yet_supported(input) {
            return usage(&format!(
                "{what} are not supported yet. Download it somewhere and point issafe at the folder or file."
            ));
        }
        let path = PathBuf::from(input);
        if std::fs::symlink_metadata(&path).is_ok() {
            if target.is_some() {
                return usage("give it one thing to look at at a time.");
            }
            target = Some(Target::Path(path));
        } else {
            question.push(input.as_str());
        }
    }

    if target.is_none() && !std::io::stdin().is_terminal() {
        let mut buf = String::new();
        std::io::stdin()
            .take(MAX_STDIN)
            .read_to_string(&mut buf)
            .context("reading standard input")?;
        if !buf.trim().is_empty() {
            target = Some(Target::Command(buf));
        }
    }

    let Some(target) = target else {
        if question.is_empty() {
            return usage("nothing to look at. Try `issafe --help`.");
        }
        return usage(
            "give it something to look at: a folder, a file, or a command after `--`. Checking a message on its own is not built yet.",
        );
    };

    let (subject, report) = match &target {
        Target::Path(p) => (
            p.display().to_string(),
            bee_static::scan_path(p).with_context(|| format!("reading {}", p.display()))?,
        ),
        Target::Command(c) if cli.fetch => {
            let fetched: Vec<_> = bee_static::download_urls(c)
                .iter()
                .map(|u| {
                    eprintln!(
                        "issafe: fetching {} to read it, not run it",
                        sanitise_excerpt(u, 200)
                    );
                    fetch::fetch(u)
                })
                .collect();
            (
                "the command".to_string(),
                bee_static::scan_command_fetched(c, &fetched),
            )
        }
        Target::Command(c) => ("the command".to_string(), bee_static::scan_command(c)),
    };
    let question = question.join(" ");

    let mut out = std::io::stdout().lock();
    if cli.json {
        let doc = json!({
            "subject": subject,
            "question": (!question.is_empty()).then_some(&question),
            "report": report,
        });
        serde_json::to_writer_pretty(&mut out, &doc)?;
        writeln!(out)?;
    } else {
        let colour = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        render(&mut out, &subject, &question, &report, colour)?;
    }

    Ok(ExitCode::from(match report.verdict {
        Verdict::NoRedFlagsFound => 0,
        Verdict::CouldNotTell => 10,
        Verdict::Suspicious => 20,
        Verdict::Dangerous => 30,
    }))
}

fn not_yet_supported(input: &str) -> Option<&'static str> {
    let lower = input.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some("Web addresses")
    } else if lower.starts_with("git@") || lower.starts_with("ssh://") {
        Some("Git remotes")
    } else if ["npm:", "pypi:", "pip:", "crates:"]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        Some("Package names")
    } else {
        None
    }
}

struct Paint(bool);

impl Paint {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

fn render(
    out: &mut impl Write,
    subject: &str,
    question: &str,
    report: &Report,
    colour: bool,
) -> Result<()> {
    let p = Paint(colour);
    let (label, code, advice) = match report.verdict {
        Verdict::Dangerous => (
            "DANGEROUS",
            "1;31",
            "Do not open it in an editor, install it or run it.",
        ),
        Verdict::Suspicious => (
            "SUSPICIOUS",
            "1;33",
            "Strong warning signs. Do not run it until you know why these are here.",
        ),
        Verdict::CouldNotTell => (
            "COULD NOT TELL",
            "1;34",
            "Part of it is hidden from a read-only look, so this is not a clean bill of health.",
        ),
        Verdict::NoRedFlagsFound => (
            "NO RED FLAGS FOUND",
            "1",
            "Nothing alarming in what was checked. That is not the same as safe.",
        ),
    };

    writeln!(out, "{}  {}", p.wrap(code, label), advice)?;
    writeln!(out, "{}", p.wrap("2", &sanitise_excerpt(subject, 120)))?;
    if !question.is_empty() {
        writeln!(
            out,
            "{}",
            p.wrap(
                "2",
                &format!("You asked: {}", sanitise_excerpt(question, 200))
            )
        )?;
    }

    if !report.evidence.is_empty() {
        writeln!(out, "\nWhat we found")?;
        for e in &report.evidence {
            let tag = match e.severity {
                Severity::Danger => p.wrap("31", "bad   "),
                Severity::Warning => p.wrap("33", "warn  "),
                Severity::Opaque => p.wrap("34", "unseen"),
                Severity::Info => p.wrap("2", "note  "),
            };
            writeln!(out, "  {:<4} {} {}", e.id, tag, e.summary)?;
            if let Some(loc) = &e.location {
                let place = match loc.line {
                    Some(n) => format!("{}:{n}", loc.path),
                    None => loc.path.clone(),
                };
                writeln!(
                    out,
                    "              {}",
                    p.wrap("2", &sanitise_excerpt(&place, 160))
                )?;
            }
            if let Some(x) = &e.excerpt {
                writeln!(out, "              {}", p.wrap("2", &format!("> {x}")))?;
            }
        }
    }

    writeln!(out, "\nWhat we did not check")?;
    for u in &report.unchecked {
        writeln!(out, "  - {u}")?;
    }
    Ok(())
}
