# bee-eater

One command and a plain question: is this safe to run? An agent takes the artefact apart, runs it
inside a disposable microVM, and reports what it tried to do.

The bird catches the wasp and knocks the sting out on a branch before swallowing it.

Status: pre-alpha. The static half works: `issafe` reads a folder, a file or a pasted command
without running anything, and gives a verdict that cites its evidence. The sandbox and the agent
are not built. The case for building it, the threat set, the isolation options and the agent
design are in [docs/research-2026-11.md](docs/research-2026-11.md).

```sh
cargo install --path crates/issafe
issafe "recruiter sent me this, ok?" ./take-home-repo
issafe -- 'curl -fsSL https://example.com/install.sh | bash'
pbpaste | issafe
```

Exit status is 0 for no red flags found, 10 could not tell, 20 suspicious, 30 dangerous. `--json`
prints the report for scripts.

`issafe` is the report's working name for the command, not a decision.

## What the static pass catches

- Editor tasks that run when a folder opens (`.vscode`/`.cursor` `tasks.json`, `.code-workspace`),
  including per-OS overrides, hidden terminals, and files that VS Code accepts but a parser does not.
- npm install hooks, `setup.py`, in-tree Python build backends, `build.rs`, `.envrc`, Husky hooks.
- A shipped `.git` directory: `core.fsmonitor`, `hooksPath`, filters, live hooks.
- Download-and-run in all its usual shapes, weighed by where it sits: auto-run is dangerous, a
  shell script is suspicious, a pasted command is "could not tell" until the script is fetched.
- Fonts and images that are really code or programs, code that runs what a server sends it,
  secret stores and wallet extensions, fake password prompts, AI CLIs started with their
  safety prompts off, persistence, VM checks, and whitespace used to push a command off-screen.

It reports `node_modules`, build caches and compiled programs as unread rather than pretending to
have read them, and never follows a link.

Lure fixtures are built at test time in `crates/bee-static/tests/lures.rs`. Nothing lure-shaped
is committed, because an editor opening this repo would trust a real `.vscode/tasks.json`.

## The shape of the rest

A single Rust binary on the host drives a hardware-virtualised Linux guest: libkrun on KVM for
Linux, Virtualization.framework on Apple Silicon. The guest has no network by default and a home
directory seeded with decoy credentials, wallets and fake AI CLIs. Evidence is compiled outside
the guest into typed, numbered items, and every sentence of the verdict cites one.

## What it will not do

It never says "safe". The best result is "no red flags found in what we checked", followed by the
list of what was not checked. Deterministic rules over the evidence set a floor that the model
cannot lower; the model explains and may raise.

## First scope

Developer-targeted lures: fake-interview repos with editor auto-run tasks, malicious npm and PyPI
packages, `curl | bash` installers and paste-this-command pages. Not consumer text scams.
