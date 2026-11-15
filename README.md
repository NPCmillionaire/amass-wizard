# amass-wizard

Interactive install & configuration wizard for **OWASP Amass v5**.

Amass v5 supports **48 API-key-capable data sources**, but configuring them means hand-editing `datasources.yaml` with six different credential shapes and zero feedback when something is wrong. This wizard walks you through all 48, one at a time: opens the signup page, takes the key, validates it against the live API, and writes it in the right shape.

## Install

```bash
git clone https://github.com/NPCmillionaire/amass-wizard
cd amass-wizard
chmod +x amass_wizard.sh
```

Requirements:
- **Amass v5** (`brew install amass`)
- **yq** (mikefarah v4) — `brew install yq` — used for safe YAML merges
- `curl`, `jq` — for live key validation
- macOS (`open`) or Linux (`xdg-open`) for the "open link" step

## Usage

```bash
./amass_wizard.sh          # interactive wizard
./amass_wizard.sh --check  # status only
./amass_wizard.sh --all    # non-interactive, defaults only
```

At the prompt:

- **`list`** — show all 48 sources, ✔ next to the ones already configured
- **`<source name>`** — e.g. `Censys` — walk through that one source
- **`all`** — walk through everything
- **`done`** — finish

Per source you get the signup/key-page URL, `[o]pen` to launch it in your browser, `[e]nter key` (hidden input), `[s]kip`. Progress shows like `9/48 sources configured`.

## What it validates

Before saving, these sources get a live API ping, so a typo doesn't become a silently-dead entry:

| Source | Check |
|---|---|
| Shodan | `GET /api-info` |
| Censys | `GET /api/v2/account` (key + secret) |
| GitHub | `GET /user` with the token |
| GitLab | `GET /api/v4/user` with `PRIVATE-TOKEN` |
| SecurityTrails | `GET /v1/ping` |
| BinaryEdge | `GET /v1/user/subscription` |
| VirusTotal | users endpoint |

URLScan gets a format check only (no cheap validate endpoint). Everything else saves marked "no online check available."

## Credential shapes supported

All six shapes from [`examples/datasources.yaml`](https://github.com/owasp-amass/amass/blob/master/examples/datasources.yaml) in the amass repo:

- `account.apikey` — most sources
- `account.apikey` + `account.secret` — Censys
- `account.username` + `account.password` — CIRCL, Spamhaus, ZoomEye
- `account.username` + `account.apikey` — PassiveTotal, FOFA, Yandex, CertCentral
- `account1` / `account2` apikeys — C99
- `app1` / `app2` with key+secret — FacebookCT

## Safety

- Writes only to `~/.config/amass/datasources.yaml` and `~/.config/amass/config.yaml`
- Upsert by source name — running twice never duplicates a Shodan
- Keys are read with hidden input, never echoed
- Files locked to `600` after every write
- Per-source TTLs pre-filled to the amass defaults (Shodan 7 days, Chaos/GitLab 3 days, etc.)

## Why

See the write-up: [Half Your Amass Sources Are Silent. I Counted, Then Built the Wizard.](
https://medium.com/@NPCmillionaire) — and the proposal on the amass repo: [owasp-amass/amass#1159](https://github.com/owasp-amass/amass/issues/1159).

## License

MIT
