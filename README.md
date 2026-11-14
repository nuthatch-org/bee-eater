# bee-eater

One command and a plain question: is this safe to run? An agent takes the artefact apart, runs it
inside a disposable microVM, and reports what it tried to do.

The bird catches the wasp and knocks the sting out on a branch before swallowing it.

Status: research only. Nothing is built. The case for building it, the threat set, the isolation
options and the agent design are in [docs/research-2026-11.md](docs/research-2026-11.md).

## The shape of it

```sh
issafe "recruiter sent me this, ok?" ./take-home-repo
issafe -- 'curl -fsSL https://x | bash'
issafe npm:left-pad@1.3.0
```

`issafe` is the report's working name for the command, not a decision.

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
