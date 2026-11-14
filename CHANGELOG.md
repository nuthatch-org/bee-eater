# Changelog

## [0.1.0] - 2026-11-14

First release. Pre-alpha: the static half works, the sandbox that runs things does not exist yet,
so every verdict is from reading, never from watching.

- `issafe <folder|file>`: reads without running anything. Editor folder-open tasks, install hooks,
  a shipped `.git`, download-and-run in its usual shapes, files disguised as fonts and images,
  secret stores, fake password prompts, AI CLIs with safety prompts off, persistence, VM checks.
- `issafe -- '<command>'` and `pbpaste | issafe` for pasted commands; `--fetch` reads the script
  such a command would download, without running it.
- `issafe npm:<name>@<version>` and `issafe pypi:<name>==<version>`: one published version,
  hash-checked against the registry and unpacked inert.
- `issafe https://github.com/<owner>/<repo>`: a bare shallow clone read blob by blob, never
  checked out, plus a pass over recent history for scrubbed lures and rotating download hosts.
- `issafe --shell-init zsh`: holds risky-looking lines on Enter until they are checked.
- `issafe --doctor`: whether this machine has what the sandbox will need.
- Verdicts are never "safe": no red flags found, could not tell, suspicious, dangerous, each
  citing numbered evidence and listing what was not checked.
