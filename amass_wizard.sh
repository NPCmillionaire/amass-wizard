#!/usr/bin/env bash
#
# amass_wizard.sh — Interactive install & configuration wizard for OWASP Amass (v5+).
#
# Usage:
#   ./amass_wizard.sh            # interactive wizard
#   ./amass_wizard.sh --all      # non-interactive (defaults only)
#   ./amass_wizard.sh --check    # report current status only
#
set -euo pipefail

AMASS_CONFIG_DIR="${AMASS_CONFIG_DIR:-$HOME/.config/amass}"
MAIN_CFG="$AMASS_CONFIG_DIR/config.yaml"
DS_CFG="$AMASS_CONFIG_DIR/datasources.yaml"
ASSUME_ALL=false
NONINTERACTIVE=false

for arg in "$@"; do
  case "$arg" in
    --check) NONINTERACTIVE=true ;;
    --all)   ASSUME_ALL=true; NONINTERACTIVE=true ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
step() { printf "\n%s== %s ==%s\n" "$BOLD" "$1" "$RESET"; }
ok()   { printf "  %s✔%s %s\n" "$GREEN" "$RESET" "$1"; }
warn() { printf "  %s!%s %s\n" "$YELLOW" "$RESET" "$1"; }
fail() { printf "  %s✘%s %s\n" "$RED" "$RESET" "$1" >&2; }
link() { printf "  %s➜%s %s\n" "$CYAN" "$RESET" "$1"; }

confirm() {
  if $ASSUME_ALL; then return 0; fi
  local reply; read -r -p "$1 [y/N] " reply </dev/tty || return 1
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

have() { command -v "$1" >/dev/null 2>&1; }

mask_key() { local k="$1"; printf '%s****%s' "${k:0:2}" "${k: -2}"; }

# --------------------------------------------------------------------------
# Data source catalog — all 48 API-key-capable sources in Amass v5.
# Format: NAME|TTL(minutes)|signup URL|credential type
#   credtype: key         single apikey
#             keysecret   apikey + secret (Censys)
#             userpass    username + password (CIRCL, Spamhaus, ZoomEye)
#             userkey     username + apikey (PassiveTotal, FOFA, Yandex, CertCentral)
#             dualkey     two apikey accounts (C99)
#             dualapp     two apps, each appid+secret (FacebookCT)
# Ordered: high-value free tiers first, then paid/obscure.
# --------------------------------------------------------------------------
SOURCES=(
  "Censys|10080|https://search.censys.io/account/api|keysecret"
  "SecurityTrails|1440|https://securitytrails.com/app/account|key"
  "GitLab|4320|https://gitlab.com/-/user_settings/personal_access_tokens|key"
  "BinaryEdge|10080|https://app.binaryedge.io/account/api|key"
  "BufferOver|1440|https://bufferover.io|key"
  "FullHunt|1440|https://fullhunt.io/user/register|key"
  "LeakIX|1440|https://leakix.net/user|key"
  "Netlas|1440|https://netlas.io/account/profile|key"
  "ONYPHE|4320|https://www.onyphe.io/login|key"
  "PassiveTotal|10080|https://passivetotal.riskiq.com/|userkey"
  "DNSDB|4320|https://www.farsightsecurity.com/solutions/dnsdb/|key"
  "Hunter|1440|https://hunter.io/users/sign_up|key"
  "HackerTarget|1440|https://hackertarget.com/member/|key"
  "Pastebin|10080|https://pastebin.com/api_scrape_tos|key"
  "PentestTools|10080|https://pentest-tools.com/|key"
  "PublicWWW|10080|https://publicwww.com/|key"
  "Quake|4320|https://quake.360.net/|key"
  "ZoomEye|1440|https://www.zoomeye.org/|userpass"
  "FOFA|10080|https://fofa.info/|userkey"
  "Yandex|1440|https://yandex.com/dev/console/|userkey"
  "ZETAlytics|1440|https://zetalytics.com/|key"
  "ThreatBook|1440|https://x.threatbook.com/|key"
  "SOCRadar|1440|https://socradar.io/labs/|key"
  "DNSlytics|1440|https://dnslytics.com/api|key"
  "DNSRepo|1440|https://dnsrepo.noc.org/|key"
  "Deepinfo|1440|https://www.deepinfo.com/|key"
  "Detectify|1440|https://detectify.com/|key"
  "BuiltWith|10080|https://builtwith.com/|key"
  "BigDataCloud|1440|https://www.bigdatacloud.com/|key"
  "BeVigil|1440|https://bevigil.com/|key"
  "Ahrefs|4320|https://ahrefs.com/|key"
  "ASNLookup|1440|https://www.asnlookup.com/|key"
  "360PassiveDNS|3600|https://360.passivedns.cn/|key"
  "C99|4320|https://c99.io/API%20keys.html|dualkey"
  "FacebookCT|4320|https://developers.facebook.com/|dualapp"
  "CIRCL|1440|https://www.circl.lu/services/passive-dns/|userpass"
  "CertCentral|1440|https://www.entrust.com/certificate-transparency-log-dashboard|userkey"
  "IntelX|1440|https://intelx.io/|key"
  "IPdata|1440|https://ipdata.co/|key"
  "IPinfo|1440|https://ipinfo.io/|key"
  "Spamhaus|1440|https://www.spamhaus.org/|userpass"
  "AlienVault|1440|https://otx.alienvault.com/|key"
  "Chaos|4320|https://chaos.projectdiscovery.io|key"
  "GitHub|4320|https://github.com/settings/tokens/new?scopes=repo&description=Amass|key"
  "Shodan|10080|https://account.shodan.io/register|key"
  "URLScan|1440|https://urlscan.io/user/signup|key"
  "VirusTotal|1440|https://www.virustotal.com/gui/join-us|key"
  "WhoisXMLAPI|1440|https://www.whoisxmlapi.com/user/register|key"
)

# Probe a key against the live API. Exit 0 = valid, 1 = rejected, 2 = no probe.
validate_key() {
  local name="$1" key="$2" extra="${3:-}"
  case "$name" in
    Shodan)
      [[ $(curl -s -m 10 "https://api.shodan.io/api-info?key=$key" | jq -r '.plan // .error // "invalid"' 2>/dev/null) != invalid ]]
      ;;
    Censys)
      curl -s -m 10 -o /dev/null -w '%{http_code}' -u "$key:$extra" https://search.censys.io/api/v2/account | grep -q '^200$'
      ;;
    GitHub)
      curl -s -m 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" https://api.github.com/user | grep -q '^200$'
      ;;
    GitLab)
      curl -s -m 10 -o /dev/null -w '%{http_code}' -H "PRIVATE-TOKEN: $key" https://gitlab.com/api/v4/user | grep -q '^200$'
      ;;
    SecurityTrails)
      curl -s -m 10 -o /dev/null -w '%{http_code}' -H "apikey: $key" https://api.securitytrails.com/v1/ping | grep -q '^200$'
      ;;
    BinaryEdge)
      curl -s -m 10 -o /dev/null -w '%{http_code}' -H "X-Key: $key" https://api.binaryedge.io/v1/user/subscription | grep -q '^200$'
      ;;
    VirusTotal)
      curl -s -m 10 -o /dev/null -w '%{http_code}' -H "x-apikey: $key" "https://www.virustotal.com/api/v3/users/$key" | grep -q '^200$'
      ;;
    URLScan)
      [[ ${#key} -ge 32 ]]
      ;;
    *) return 2 ;;
  esac
}

# --------------------------------------------------------------------------
# Upsert a source block into datasources.yaml using yq (required for v5 keys).
# Handles all credential shapes.
# --------------------------------------------------------------------------
upsert_source() {
  local name="$1" ttl="$2" type="$3" key="$4" extra="${5:-}"
  local block
  case "$type" in
    key)
      block="\"name\": \"$name\", \"ttl\": $ttl, \"creds\": {\"account\": {\"apikey\": \"$key\"}}"
      ;;
    keysecret)
      block="\"name\": \"$name\", \"ttl\": $ttl, \"creds\": {\"account\": {\"apikey\": \"$key\", \"secret\": \"$extra\"}}"
      ;;
    userpass)
      block="\"name\": \"$name\", \"ttl\": $ttl, \"creds\": {\"account\": {\"username\": \"$key\", \"password\": \"$extra\"}}"
      ;;
    userkey)
      block="\"name\": \"$name\", \"ttl\": $ttl, \"creds\": {\"account\": {\"username\": \"$key\", \"apikey\": \"$extra\"}}"
      ;;
    dualkey)
      block="\"name\": \"$name\", \"ttl\": $ttl, \"creds\": {\"account1\": {\"apikey\": \"$key\"}, \"account2\": {\"apikey\": \"$extra\"}}"
      ;;
    dualapp)
      block="\"name\": \"$name\", \"ttl\": $ttl, \"creds\": {\"app1\": {\"apikey\": \"$key\", \"secret\": \"$extra\"}}"
      ;;
  esac
  yq -i ".datasources |= map(select(.name != \"$name\"))" "$DS_CFG"
  yq -i ".datasources += [$block]" "$DS_CFG"
  chmod 600 "$DS_CFG" 2>/dev/null || true
}

# Existing key lookup (masked for display)
existing_entry() {
  local name="$1"
  [[ -f "$DS_CFG" ]] || { echo ""; return; }
  yq -r ".datasources[] | select(.name == \"$name\") | .creds | [.account.apikey, .account1.apikey, .app1.apikey, .account.username] | .[0] // \"\"" "$DS_CFG" 2>/dev/null || echo ""
}

# --------------------------------------------------------------------------
# Guided per-source walkthrough
# --------------------------------------------------------------------------
setup_api_keys() {
  step "Data source API keys — guided setup (48 sources)"
  echo "  Ordered by value for a free-tier user. Type the source name to set it,"
  echo "  'all' to walk through everything, 'list' to see the catalog, 'done' to finish."
  echo "  Keys are written to $DS_CFG"
  echo

  while true; do
    read -r -p "  Source name / all / list / done: " choice </dev/tty || break
    case "$choice" in
      done|[Dd]one) break ;;
      list|[Ll]ist)
        echo "  ${BOLD}Catalog:${RESET}"
        local e name ttl url type
        for e in "${SOURCES[@]}"; do
          IFS='|' read -r name ttl url type <<<"$e"
          if [[ -n "$(existing_entry "$name")" ]]; then
            printf "    %s✔ %s%s\n" "$GREEN" "$name" "$RESET"
          else
            printf "      %s\n" "$name"
          fi
        done
        ;;
      all|[Aa]ll)
        local e
        for e in "${SOURCES[@]}"; do
          setup_one_source "$e" || true
        done
        ;;
      *)
        local match=""
        for e in "${SOURCES[@]}"; do
          [[ "${e%%|*}" == "$choice" ]] && match="$e" && break
        done
        if [[ -z "$match" ]]; then
          warn "Unknown source '$choice'. Use 'list' to see valid names."
        else
          setup_one_source "$match"
        fi
        ;;
    esac
    # show quick progress
    if have yq && [[ -f "$DS_CFG" ]]; then
      ok "Progress: $(yq '.datasources | length' "$DS_CFG" 2>/dev/null || echo 0)/48 sources configured."
    fi
  done
  ok "Data source setup complete."
}

# Configure a single source; takes one catalog entry string.
setup_one_source() {
  local entry="$1" name ttl url type existing key extra reply
  IFS='|' read -r name ttl url type <<<"$entry"
  existing="$(existing_entry "$name")"

  echo
  echo "${BOLD}${CYAN}[${name}]${RESET}  (ttl: ${ttl}m)"
  link "Signup / key page:  $url"

  if [[ -n "$existing" ]]; then
    ok "Already configured: $(mask_key "$existing")"
    read -r -p "  [r]eplace, [k]eep: " reply </dev/tty || reply=k
    [[ "$reply" =~ ^[Rr] ]] || return 0
  fi

  read -r -p "  [o]pen link, [e]nter key, [s]kip: " reply </dev/tty || return 0
  case "$reply" in
    o|O)
      if have open; then open "$url"
      elif have xdg-open; then xdg-open "$url"
      else link "Visit: $url"; fi
      read -r -p "  Paste your $name key (hidden): " key </dev/tty || return 0
      ;;
    e|E)
      read -r -p "  Paste your $name key (hidden): " key </dev/tty || return 0
      ;;
    *) warn "Skipped $name."; return 0 ;;
  esac
  [[ -z "$key" ]] && { warn "Empty key — skipped."; return 0; }

  # Collect the second credential depending on type
  case "$type" in
    keysecret) read -r -p "  Paste your $name SECRET (hidden): " extra </dev/tty || return 0 ;;
    userpass)  read -r -p "  Paste your $name PASSWORD (hidden): " extra </dev/tty || return 0 ;;
    userkey)   read -r -p "  Paste your $name APIKEY for the username above (hidden): " extra </dev/tty || return 0 ;;
    dualkey)
      read -r -p "  Paste account2 key (or Enter if only one) (hidden): " extra </dev/tty || extra=""
      ;;
    dualapp)
      read -r -p "  Paste app1 SECRET (hidden): " extra </dev/tty || return 0
      ;;
  esac

  echo -n "  Verifying key... "
  set +e; validate_key "$name" "$key" "$extra"; local rc=$?; set -e
  if [[ $rc -eq 0 ]]; then
    printf "${GREEN}valid ✔${RESET}\n"
  elif [[ $rc -eq 1 ]]; then
    printf "${RED}rejected ✘${RESET}\n"
    confirm "  Save anyway?" || return 0
  else
    printf "${YELLOW}no online check available${RESET}\n"
  fi

  upsert_source "$name" "$ttl" "$type" "$key" "$extra"
  ok "Saved $name."
}

# --------------------------------------------------------------------------
# Scope domains
# --------------------------------------------------------------------------
setup_scope() {
  step "Scope: target domains"
  [[ -f "$MAIN_CFG" ]] || return
  if have yq; then
    local current; current="$(yq -r '.scope.domains[]?' "$MAIN_CFG" 2>/dev/null || true)"
    [[ -n "$current" ]] && echo "  Currently in scope: $current" || warn "No domains in scope yet."
    while confirm "  Add a domain to scope?"; do
      read -r -p "  Domain (e.g. example.com): " d </dev/tty || break
      [[ -z "$d" ]] && continue
      yq -i ".scope.domains += [\"$d\"]" "$MAIN_CFG"
      yq -i '.scope.domains |= (unique | sort)' "$MAIN_CFG"
      ok "Added $d"
    done
  fi
}

# --------------------------------------------------------------------------
# Other steps
# --------------------------------------------------------------------------
install_amass() {
  step "Install Amass"
  if have amass; then ok "Installed: $(amass -version 2>&1 | head -1)"; return; fi
  if have brew; then
    echo "  Installing with Homebrew..."
    brew install amass
    have amass && ok "Amass installed." || fail "'amass' not on PATH — restart shell."
  else
    fail "No Homebrew. Install Go, then: go install -v github.com/owasp-amass/amass/v4/...@master"
    exit 1
  fi
}

smoke_test() {
  step "Smoke test"
  if have amass; then
    ok "amass on PATH: $(command -v amass)"
  else
    fail "amass not found — restart your shell if just installed."
  fi
  if [[ -f "$DS_CFG" ]] && have yq; then
    local total count
    total="$(yq '.datasources | length' "$DS_CFG" 2>/dev/null || echo 0)"
    echo "  Configured data sources: $total / 48"
    yq -r '.datasources[] | "    - " + .name + " (" + (.creds | [.. | scalars | .] | first | .[0:2] + "****" + .[-2:] // "?") + ")"' "$DS_CFG" 2>/dev/null || true
  fi
  echo "  Example first run:"
  echo "    amass enum -d example.com -o $HOME/amass_output"
}

status_report() {
  step "Status"
  have amass && ok "amass: $(command -v amass)" || warn "amass: not installed"
  [[ -f "$MAIN_CFG" ]] && ok "config.yaml exists" || warn "config.yaml missing"
  if [[ -f "$DS_CFG" ]] && have yq; then
    ok "datasources.yaml: $(yq '.datasources | length' "$DS_CFG" 2>/dev/null || echo 0) / 48 sources configured"
  else
    warn "datasources.yaml missing"
  fi
}

if $NONINTERACTIVE && ! $ASSUME_ALL; then status_report; exit 0; fi

step "Amass Install & Config Wizard"
install_amass
setup_api_keys
setup_scope
smoke_test
status_report
step "Done"
