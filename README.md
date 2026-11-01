# Argus

### &#128301; The all-seeing recon framework for bug bounty hunters.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/BeardedVikingTX/Argus/pulls)
[![Maintained](https://img.shields.io/badge/maintained-yes-green.svg)](https://github.com/BeardedVikingTX/Argus)

    Argus (Ἄργος) — the hundred-eyed giant of Greek myth. The all-seeing watchman. A modular, file-driven recon pipeline that chains subdomain enumeration, liveness detection, service scanning, URL mining, and heuristic candidate flaggers into one clean, idempotent workflow.

Argus does not exploit. Argus surfaces. Every finding it produces is a candidate — a flag on a map that says "look here, human." Manual triage is the point. That's what separates real findings from duplicate noise.

# 📖 Table of Contents
--------------------

-   Why Argus

-   The Pipeline

-   Features

-   Installation

-   Quick Start

-   Usage

-   Module Reference

-   Output Structure

-   Configuration

-   Ethics, Scope & Legal

-   Roadmap

-   Contributing

-   Author & Contact

-   License

* * * * *

# 🎯 Why Argus
------------

Most bug bounty tooling falls into two camps: **massive all-in-one frameworks** that are hard to reason about and slower to adapt, or **loose piles of bash scripts** that break the moment a tool changes its output format.

Argus sits in the middle. It's **modular by design** --- every stage is a self-contained Python module that reads a file and writes a file. That means:

-   **Rerun any stage independently** without re-running the whole pipeline.

-   **Swap out any tool** (subfinder → amass, httpx → your own prober) without touching the rest.

-   **Extend trivially** --- drop a new module into `auditing_tools/`, wire it into `main.py`, done.

-   **Audit the output** --- every stage leaves a deterministic file in `output/`, so you can inspect *exactly* how a candidate was discovered.

Recon is the game. Argus makes the game repeatable.

* * * * *

# 🔧 The Pipeline
---------------

```
wildcard.txt
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 1 · RECON                                            │
│                                                             │
│   subfinder + assetfinder ──▶  output/all_subs.txt          │
│   httpx (live / status / title / tech) ──▶  live_hosts.txt  │
│   nmap (top-1000 -sV -sC) ──▶  nmap_fast.*                  │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 2 · AUDIT                                            │
│                                                             │
│   katana + waybackurls ──▶  output/all_urls.txt             │
│   parameter extraction ──▶  interesting_urls.txt            │
│                                                             │
│   sqli_finder   ──▶  sqli_candidates.txt                    │
│   xss_finder    ──▶  xss_candidates.txt                     │
│   ssrf_finder   ──▶  ssrf_candidates.txt                    │
│   ssti_finder   ──▶  ssti_candidates.txt   (roadmap)        │
│   idor_finder   ──▶  idor_candidates.txt   (roadmap)        │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
  You. Burp Suite. Manual triage.
wildcard.txt
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 1 · RECON                                            │
│                                                             │
│   subfinder + assetfinder ──▶  output/all_subs.txt          │
│   httpx (live / status / title / tech) ──▶  live_hosts.txt  │
│   nmap (top-1000 -sV -sC) ──▶  nmap_fast.*                  │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 2 · AUDIT                                            │
│                                                             │
│   katana + waybackurls ──▶  output/all_urls.txt             │
│   parameter extraction ──▶  interesting_urls.txt            │
│                                                             │
│   sqli_finder   ──▶  sqli_candidates.txt                    │
│   xss_finder    ──▶  xss_candidates.txt                     │
│   ssrf_finder   ──▶  ssrf_candidates.txt                    │
│   ssti_finder   ──▶  ssti_candidates.txt   (roadmap)        │
│   idor_finder   ──▶  idor_candidates.txt   (roadmap)        │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
  You. Burp Suite. Manual triage.
```

# ✨ Features
----------

-   **🔗 Fully modular** --- one module per stage, no hidden coupling, no monolithic scripts.

-   **📁 File-based chaining** --- deterministic filenames in `output/`; rerun any stage safely.

-   **⚡ Idempotent** --- rerunning a stage overwrites cleanly, never double-appends.

-   **🛡️ Triage-first** --- every "finding" is flagged for a human to verify. Argus never submits anything on your behalf.

-   **🐍 Pure Python + CLI hybrid** --- orchestration in Python, heavy lifting delegated to the community-standard CLI tools you already trust.

-   **📊 Structured output** --- tab-separated candidate files, ready to grep, diff, or feed into your own scripts.

-   **🔇 Silent-by-default logging** --- clean stdout for humans, verbose `output/run.log` for debugging.

-   **🧪 Gracefully degrades** --- a missing optional tool logs a warning, it doesn't kill the run.

-   **🧭 Scope-aware by design** --- designed to filter against an out-of-scope list before any active testing.

-   **⚖️ Rate-limit conscious** --- threaded but throttled; intended to respect program limits (see Ethics).

* * * * *

# 📦 Installation
---------------

### Prerequisites

-   **Python 3.10+**

-   **Go 1.19+** (for ProjectDiscovery and TomNomNom tools)

-   **nmap** (system package)

-   **Linux / macOS** (WSL2 works on Windows)

### One-shot install

```
git clone https://github.com/BeardedVikingTX/Argus.git
cd Argus
chmod +x tools.sh
./tools.sh
```

`tools.sh` installs system packages, Python deps, and the following Go tools:

| Tool | Purpose |
| --- | --- |
| [`subfinder`](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration |
| [`assetfinder`](https://github.com/tomnomnom/assetfinder) | Secondary subdomain source |
| [`httpx`](https://github.com/projectdiscovery/httpx) | HTTP probing, liveness, tech detection |
| [`katana`](https://github.com/projectdiscovery/katana) | Modern JS-aware web crawler |
| [`waybackurls`](https://github.com/tomnomnom/waybackurls) | Historical URL mining |
| [`nmap`](https://nmap.org/) | Port + service scanning |

After install, make sure `$(go env GOPATH)/bin` is in your `$PATH`.

### Python deps

```
pip install -r requirements.txt
```

# 🚀 Quick Start
```
# 1. Add your target wildcard(s) — one per line
echo "example.com" > wildcard.txt
echo "example.org" >> wildcard.txt

# 2. Run the full pipeline
python3 main.py --stage all

# 3. Review the output
ls output/
less output/live_hosts.txt
less output/sqli_candidates.txt
```
Or run stages independently:
```
python3 main.py --stage recon    # subdomains → live hosts → nmap
python3 main.py --stage audit    # crawl → flaggers
```

## 🧑‍💻 Usage
### CLI
```
usage: main.py [-h] [--stage {recon,audit,all}]

options:
  -h, --help            show this help message and exit
  --stage {recon,audit,all}
                        Stage to execute (default: all)
```

### Examples
```
# Full pipeline
python3 main.py --stage all

# Recon only (safe to rerun weekly — diff all_subs.txt for new assets)
python3 main.py --stage recon

# Audit only (assumes recon has been run at least once)
python3 main.py --stage audit
```

### Adding a new module
```
# auditing_tools/ssti_finder.py
def run_ssti_scan(url_file, outdir):
    ...


# main.py
from auditing_tools.ssti_finder import run_ssti_scan
...
if args.stage in ("audit", "all"):
    run_ssti_scan(urls, OUT)
```

That's it. No registry, no config file, no framework boilerplate.

📚 Module Reference
-------------------

### Recon stage

| Module | Reads | Writes | Notes |
| --- | --- | --- | --- |
| `recon_tools/subs.py` | `wildcard.txt` | `all_subs.txt` | Aggregates subfinder + assetfinder, dedupes |
| `recon_tools/sub_discover.py` | `all_subs.txt` | `live_hosts.txt` | HTTPX with status, title, tech detection |
| `recon_tools/nmap.py` | `live_hosts.txt` | `nmap_fast.*` | `-sS -sV -T4` on top-1000 ports; `-sT` fallback for non-root |

### Audit stage

| Module | Reads | Writes | Signal tested |
| --- | --- | --- | --- |
| `auditing_tools/site_mapping.py` | `live_hosts.txt` | `all_urls.txt`, `interesting_urls.txt` | katana crawl + wayback; tags `/api`, `/graphql`, `/admin`, `/actuator`, swagger, etc. |
| `auditing_tools/sqli_finder.py` | `all_urls.txt` | `sqli_candidates.txt` | Error-signature match + response-length anomaly |
| `auditing_tools/xss_finder.py` | `all_urls.txt` | `xss_candidates.txt` | Unencoded marker reflection in parameter context |
| `auditing_tools/ssrf_finder.py` | `all_urls.txt` | `ssrf_candidates.txt` | URL-ish param names probed with metadata target |
| `auditing_tools/ssti_finder.py`  *(roadmap)* | `all_urls.txt` | `ssti_candidates.txt` | Template-expression reflection |
| `auditing_tools/idor_finder.py`  *(roadmap)* | `all_urls.txt` | `idor_candidates.txt` | Numeric/UUID identifier surface extraction |

* * * * *

📂 Output Structure
-------------------
```
output/
├── run.log                  # Full run log (timestamped, module-tagged)
├── all_subs.txt             # All discovered subdomains (deduped, sorted)
├── live_hosts.txt           # httpx output: URL, status, title, tech
├── live_hosts_ips.txt       # Stripped hostnames for nmap
├── nmap_fast.nmap           # Human-readable nmap output
├── nmap_fast.xml            # Machine-readable nmap output
├── nmap_fast.gnmap          # Grepable nmap output
├── all_urls.txt             # Every URL from katana + waybackurls
├── interesting_urls.txt     # Filtered: api, graphql, admin, swagger, ...
├── sqli_candidates.txt      # type ⇥ param ⇥ payload ⇥ url
├── xss_candidates.txt       # param ⇥ payload ⇥ url
└── ssrf_candidates.txt      # note ⇥ param ⇥ url
```

Candidate files are **tab-separated** so `awk`, `cut`, and `grep` work cleanly on them.

⚙️ Configuration
----------------

Argus intentionally ships with **no YAML config** --- the whole surface is:

| File | Purpose |
| --- | --- |
| `wildcard.txt` | Your in-scope root domains, one per line |
| `out_of_scope.txt`  *(optional)* | Hosts/subdomains to strip before Stage 2 |
| `requirements.txt` | Python deps |

If you need tuning, edit the constants at the top of the relevant module. That's the feature --- the configuration is the source code.

* * * * *

⚖️ Ethics, Scope & Legal
------------------------

**Argus is a triage aid, not an auto-exploiter.** It is built for **authorized security testing only** --- bug bounty programs, penetration tests, CTFs, and your own infrastructure.

Before you run Argus against any target, you must:

1.  **Read the program's scope.** Wildcards are almost never "everything under the sun." Verify every discovered host against the published in-scope list.

2.  **Respect rate limits.** Many programs specify max requests/second. Throttle accordingly --- the `ThreadPoolExecutor(max_workers=N)` and per-request `timeout=` values in the finder modules are where you tune this.

3.  **Never use Argus to confirm a finding by exploitation.** It flags candidates. You verify them in Burp, manually, within the program's rules of engagement.

4.  **Handle out-of-scope assets responsibly.** If you discover a host that's out of scope, stop. Don't probe it. Report it to the program if it looks like a real exposure.

**The author assumes no liability for misuse.** Running Argus against infrastructure you don't own and aren't authorized to test is illegal in most jurisdictions, violates the CFAA (US), the Computer Misuse Act (UK), and equivalent laws elsewhere, and will get you banned from every major platform. Do not do it.

If you're new to bug bounty: read [HackerOne's disclosure guidelines](https://www.hackerone.com/disclosure-guidelines), [ProjectDiscovery's ethics page](https://github.com/projectdiscovery), and the rules of every program before you point a scanner at it.

* * * * *

🗺️ Roadmap
-----------

-   ☑ Modular pipeline: subdomains → live → nmap → URLs → flaggers

-   ☑ File-based, idempotent stages

-   ☑ SQLi / XSS / SSRF candidate flaggers

-   □ **`ssti_finder.py`** --- template-expression reflection detection

-   □ **`idor_finder.py`** --- numeric/UUID identifier surface extraction

-   □ **`nuclei.py`** --- template-driven CVE / misconfig / exposure scanning

-   □ **`out_of_scope.txt`** --- enforced pre-flight scope filter

-   □ **`interactsh` integration** --- OOB confirmation for blind SSRF / XSS

-   □ **`argus diff`** --- diff two runs to surface *new* assets since last week

-   □ **`argus report`** --- JSON export for ingestion into other tools

-   □ **Docker image** --- one-command deploy without local Go install

Have an idea? Open an issue.

* * * * *

🤝 Contributing
---------------

Pull requests are welcome --- especially new modules in `auditing_tools/` and additional recon sources in `recon_tools/`.

Guidelines:

-   **Keep modules stateless.** Read a file, write a file, return a path.

-   **Log with `logging.getLogger(__name__)`.** No `print()` in library modules.

-   **Wrap external tool calls in `try/except FileNotFoundError`.** Graceful degradation is a feature.

-   **Flag candidates, never confirm exploits.** This is non-negotiable.

-   **Respect rate limits in your module.** Assume every target has one.
```
# Standard contribution flow
git checkout -b feature/my-new-module
# ... implement, test against a lab target (HTB, Juice Shop, your own VPS)
git commit -m "feat: add my-new-module to auditing_tools"
git push origin feature/my-new-module
# → open a PR against main
```

👤 Author & Contact
-------------------

**BeardedVikingTX** --- builder, breaker, bug bounty hunter.

|\
 |\
 |
| --- | --- |
| 🐙 **GitHub** | [@BeardedVikingTX](https://github.com/BeardedVikingTX/Argus) |
| 💼 **LinkedIn** | [bearded-viking-3112a8431](https://www.linkedin.com/in/bearded-viking-3112a8431/) |
| 🏰 **MyCitadel** | [users/view.php?id=4](https://mycitadel.lol/users/view.php?id=4) |
| ✉️ **Email** | info@beardedviking.org |

Questions, ideas, war stories from the field --- reach out. If you find a bug in Argus, open an issue. If you find a bug *with* Argus, open a PR (and tell me where --- I'll credit you in the release notes).

* * * * *

📜 License
----------

Released under the [MIT License](https://opensource.org/licenses/MIT). Use it, fork it, build on it, ship it. Just don't use it against anything you're not authorized to test.

* * * * *

<div align="center">

**Argus sees everything. You decide what matters.**

⭐ If this saved you a duplicated report, star the repo.

</div>
