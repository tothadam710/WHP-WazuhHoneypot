import random
import re
from datetime import datetime
from typing import Dict, Optional, List

# ---------------------------
# Helper: ps preview builder
# ---------------------------
def _format_ps_example(processes: Dict[str, int], cap_per_proc:int=4):
    """
    Build a short ps/top style preview (text block) from process counts.
    Returns multiple lines like: " 1754 nginx: worker process    12.4%  2.3%"
    """
    pid = 1500
    lines = []
    # heuristic ordering: highest-count first
    for name, cnt in sorted(processes.items(), key=lambda x: -x[1])[:18]:
        display_name = name
        # nicer label if nginx present
        if "nginx" in name.lower():
            display_name = "nginx: worker process"
        display_name = display_name.replace(" ", "_")
        for i in range(min(cnt, cap_per_proc)):
            pid += random.randint(1,120)
            # cpu/mem heuristics by process type
            lname = name.lower()
            if any(x in lname for x in ("mysql","mysqld","java")):
                cpu = round(random.uniform(3.0, 20.0),1)
                mem = round(random.uniform(3.0, 18.0),1)
            elif name.startswith("kworker") or name.startswith("khung") or name.startswith("kdev"):
                cpu = round(random.uniform(0.0, 3.0),1)
                mem = round(random.uniform(0.0, 1.0),1)
            elif "unattended" in lname:
                cpu = round(random.uniform(1.0, 8.0),1)
                mem = round(random.uniform(0.2, 2.0),1)
            else:
                cpu = round(random.uniform(0.0, 6.0),1)
                mem = round(random.uniform(0.1, 3.0),1)
            lines.append(f"{pid:>5} {display_name:<28} {cpu:>5}% {mem:>5}%")
    return "\n    ".join(lines)

# --------------------------------
# Helper: package preview builder
# --------------------------------
def _format_package_preview(packages: Dict[str,int], max_show:int=12):
    """
    Build apt/dpkg-like preview lines referencing package names from inventory.
    Show installed lines and inject one plausible dpkg warning referencing an actual package.
    """
    pk_lines = []
    items = list(packages.items())[:max_show] if packages else []
    for pkg, count in items:
        # We don't have version numbers in the dict; show installed hint using count as pseudo-version hint
        pk_lines.append(f"{pkg} installed (meta-count={count})")
    if items:
        broken_pkg = items[min(2, len(items)-1)][0]
        pk_lines.append(f"dpkg: warning: while removing package {broken_pkg}: dependency problems - not fully installed (simulated)")
        pk_lines.append(f"apt: E: Sub-process /usr/bin/dpkg returned an error code (1) (simulated)")
    return "\n    ".join(pk_lines)

# --------------------------------
# Small utilities
# --------------------------------
def _most_common_value(d: Dict[str,int], default: str = "unknown") -> str:
    """Return the key with the highest count from a dict of {value: count}."""
    if not d:
        return default
    return max(d.items(), key=lambda x: x[1])[0]

def _top_n_keys(d: Dict[str,int], n:int=10) -> List[str]:
    """Return the top-n keys by frequency (descending)."""
    if not d:
        return []
    return [k for k, _ in sorted(d.items(), key=lambda x: -x[1])[:n]]

# -------------------------------------------------------
# CVE selection + package matching for "vulnerable look"
# -------------------------------------------------------
def _select_top_severe_cves(vulns: Dict, package_dict: Dict[str,int],
                            severities: List[str]=["Critical","High"],
                            top_n:int=5) -> List[Dict]:
    """
    From the vulnerabilities dict (JSON shape like your linux_profile.json),
    pick top_n CVEs that have severity in 'severities' (priority: Critical then High).
    Try to match package names referenced in the CVE example text against package_dict keys.

    Returns list of dicts:
    {
        "cve_id": str,
        "count": int,
        "severity": str,
        "matched_packages": [pkg,...],
        "example": { ... }  # chosen representative example object if present
    }
    """
    if not vulns:
        return []

    entries = []
    for cve_id, meta in vulns.items():
        count = meta.get("count", 0)
        examples = meta.get("examples", []) or []

        # choose best example preferring wanted severities
        chosen = None
        chosen_sev = ""
        for sev in severities:
            for ex in examples:
                if ex.get("severity","").lower() == sev.lower():
                    chosen = ex
                    chosen_sev = sev
                    break
            if chosen:
                break
        if not chosen and examples:
            chosen = examples[0]
            chosen_sev = chosen.get("severity","")
        if not chosen:
            chosen = {}
            chosen_sev = ""

        # combine candidate text to search for package names
        text = " ".join([str(chosen.get("condition","")), str(chosen.get("description",""))]).lower()
        matched = []
        for pkg in package_dict.keys():
            # token boundary match to avoid partial matches
            if re.search(r"\b" + re.escape(pkg.lower()) + r"\b", text):
                matched.append(pkg)

        entries.append({
            "cve_id": cve_id,
            "count": count,
            "severity": chosen_sev,
            "matched_packages": matched,
            "example": chosen
        })

    # filter by severity preference
    desired = [e for e in entries if e["severity"].lower() in [s.lower() for s in severities]]
    if len(desired) < top_n:
        # fallback to any severity if not enough matches
        desired = entries

    # sort by count desc and return top_n
    desired_sorted = sorted(desired, key=lambda x: -x["count"])
    return desired_sorted[:top_n]

# -------------------------------------------------------
# Main prompt generator
# -------------------------------------------------------
def generate_cowrie_prompt_detailed(wazuh_data: Dict, sample_zip: Optional[str]=None,
                                   top_proc_n:int=18, top_pkg_n:int=12,
                                   top_vuln_n:int=5) -> str:
    """
    Produce a detailed Cowrie honeypot generation prompt from aggregated JSON data.

    - Dynamically chooses most common OS/Version/Platform/Port.
    - Uses top N processes and top N packages for realistic previews.
    - Selects top High/Critical CVEs and attempts to match them to packages,
      then instructs the LLM to *simulate* vulnerability indicators (no exploits).
    """
    # --- dynamic OS/platform/port selection ---
    os_name = _most_common_value(wazuh_data.get("os_names", {}), "Linux")
    os_version = _most_common_value(wazuh_data.get("os_versions", {}), "unknown version")
    os_platform = _most_common_value(wazuh_data.get("os_platforms", {}), "x86_64")
    main_port = _most_common_value(wazuh_data.get("open_ports", {}), "22")

    # --- top processes & packages ---
    process_dict = wazuh_data.get("process_names", {}) or {}
    package_dict = wazuh_data.get("package_names", {}) or {}

    top_processes = _top_n_keys(process_dict, n=top_proc_n)
    top_packages = _top_n_keys(package_dict, n=top_pkg_n)

    selected_processes = {p: process_dict[p] for p in top_processes}
    selected_packages = {p: package_dict[p] for p in top_packages}

    # --- CVE selection & matching ---
    vulns = wazuh_data.get("vulnerabilities", {}) or {}
    top_vulns = _select_top_severe_cves(vulns, package_dict, severities=["Critical","High"], top_n=top_vuln_n)

    # Build a compact human-readable summary of chosen CVEs for the prompt
    vuln_summary_lines = []
    for v in top_vulns:
        ex = v.get("example", {}) or {}
        cond = ex.get("condition","")
        brief = cond if cond else ex.get("description","")
        brief = (brief[:140] + "...") if len(brief) > 140 else brief
        vuln_summary_lines.append(f"{v['cve_id']} ({v['severity']}) -> packages: {v['matched_packages'] or ['(no direct match)']} ; note: {brief}")

    vuln_preview = ", ".join([v["cve_id"] for v in top_vulns]) if top_vulns else "none"

    # --- previews for prompt ---
    ps_preview = _format_ps_example(selected_processes)
    pk_preview = _format_package_preview(selected_packages)
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    # sample human usernames
    human_users = ["admin","deploy","git","ci-runner","ops","anna","peter","nora","kevin","maria"]

    # --- Construct prompt text (instructions to LLM) ---
    prompt = f"""
You are a senior on-call Linux sysadmin and intrusion analyst. Generate a set of **highly realistic** Cowrie honeypot filesystem artifacts.
**OUTPUT MUST BE ONLY file blocks**, in this exact format (nothing else):

--- FILE: <relative/path/to/file> ---
<file content>

Use the inventory below to make the artifacts look like they came from a real {os_name} {os_version} host ({os_platform} platform).
The generated files must reference these package names and contain ps/top snapshots consistent with the running processes counts.

ENVIRONMENT (use these values)
- OS Name: {os_name}
- OS Version: {os_version}
- Platform: {os_platform}
- Open port: {main_port}

INSTALLED PACKAGES (top {len(selected_packages)} most common)
    {pk_preview}

RUNNING PROCESSES (top {len(selected_processes)} most common — ps/top style examples)
    {ps_preview}

NOTABLE CVEs (selected top severe CVEs from inventory — informational only): {vuln_preview}

VULNERABILITY SIMULATION (IMPORTANT — NO EXPLOITS)
- Based on the inventory, the following CVEs were identified as High/Critical and should be used to make the honeypot appear **deliberately vulnerable** (simulate only; DO NOT include exploit code or PoCs):
{chr(10).join(['    - ' + l for l in vuln_summary_lines]) if vuln_summary_lines else '    - none selected'}

For each listed CVE above, instruct the LLM to:
  * Show a plausible older/vulnerable package version in package lists (e.g., "zlib1g 1.2.8.dfsg-2ubuntu4.3 installed (vulnerable)").
  * In logs/cve_simulation.log add one RFC-3339 timestamped line describing an observed symptom (e.g., "gzip header parsing failed; connection reset").
  * In dpkg -l / rpm -qa / or service status outputs show the affected package and a simulated "Pending security update" or "Fix available but not applied" note.
  * Avoid any exploit, code snippet, PoC, shell commands to exploit the vulnerability, or private credentials — only textual observations and version strings.

MANDATORY FORMAT & SAFETY RULES
- DO NOT include working exploits, malware, or runnable payloads.
- DO NOT include any real credentials, real private keys, or real secrets.
- All hashes/tokens must be synthetic, random-looking strings.
- Use RFC-3339 timestamps **without fractional seconds** (e.g. {now}).
- Output ONLY file blocks; nothing outside them.
- Keep files realistic but moderately sized.

REQUIRED FILES (generate each as a file block)
1) --- FILE: etc/passwd ---
   - Include standard system accounts (root, daemon, bin, sys, sync, mail, www-data, mysql)
   - Include 10 human users (UIDs starting at 1000) — use human-like names (examples: {', '.join(human_users[:8])})
   - Home directories (/home/<user>) and shell set to /bin/bash or /bin/zsh.

2) --- FILE: etc/shadow ---
   - One line per username; use SHA-512 style $6$rounds=656000$<salt>$<randomstring> (alnum + ./).
   - Values must be synthetic and unique per user.

3) --- FILE: etc/hostname ---
   - Choose a hostname consistent with services (e.g., web-01 or app-frontend if nginx/unattended-upgr present).

4) --- FILE: etc/motd and etc/issue ---
   - Provide a distribution-style greeting that references {os_name} {os_version}.
   - Include "Last security update" date (simulated) and a short advisory like "Security updates pending: N CVE(s). See /var/log/cve_simulation.log".

5) --- FILE: cowrie.cfg ---
   - Realistic sections: [honeypot], [ssh], [shell], [output_jsonlog], [output_textlog].
   - listen_endpoints on port {main_port}; include 1–2 commented alternate ports.
   - userdb_file -> etc/userdb.txt; log files in var/log/cowrie.
   - Add a couple admin comments/TODOs (typos acceptable). No private keys.

6) --- FILE: etc/userdb.txt ---
   - One bcrypt-like token per human user: format "user:$2y$10$<22-28 chars>"
   - Tokens should vary in length/appearance.

7) --- FILE: log/cowrie.log --- and --- FILE: log/auth.log ---
   - Use RFC5737 attacker IPs: 192.0.2.x, 198.51.100.x, 203.0.113.x.
   - ***CRITICAL (must match exactly):*** the SSH listener line MUST BE exactly:
         listen_endpoints = tcp:2222:interface=0.0.0.0
   - Simulate a realistic attacker session:
       * repeated failed logins from one IP (use different usernames from /etc/passwd)
       * one successful login for a non-root user from another IP
       * cowrie.session lines: executed commands (id; uname -a; ps aux; cat /proc/cpuinfo | head -n1; sudo -l)
       * explicit session open/close lines (pam_unix session opened/closed)
       * interleave kernel/syslog noise: "TCP: Possible SYN flooding", "BUG: unable to handle kernel NULL pointer dereference", "Connection reset by peer", "broken pipe"
       * include ps/top snapshots that **use the exact process names** from the RUNNING PROCESSES snippet above (repeat worker entries with distinct PIDs)
       * when attacker inspects services (e.g., `systemctl status ufw`), include output that references packages from the INSTALLED PACKAGES preview

8) --- FILE: logs/cve_simulation.log ---
   - One RFC-3339 timestamped line per CVE from the selected top list. Each line must be observational (no exploit) and mention the CVE ID, a short symptom, and any matched package/version found.

EXTRA REALISM (encouraged)
- Add a fabricated /proc/cpuinfo single-line: "model name : Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz"
- Add systemd/CRON noise: "Started Daily apt download activities", "CRON[1234]: pam_unix(cron:session): session opened for user root"
- In cowrie.cfg, keep a commented legacy banner or alternate listen_endpoints line.

NOW: produce **ONLY** the files requested above as file blocks with the described realism, and ensure that any vulnerability indicators are observational text only (no exploit/PoC).

DEPLOYABILITY REQUIREMENT
-------------------------
- Ensure cowrie.cfg is syntactically valid for Cowrie >= 2.5.
- Use non-privileged port 2222 (not 22) in listen_endpoints.
- Use local relative paths for log_path=log and userdb_file=etc/userdb.txt.
- Point filesystem to share/cowrie/fs.pickle.
- The resulting folder must be runnable immediately with:
      bin/cowrie start
  (assuming cowrie-venv and default directory layout).

USERDB FILE FORMAT (IMPORTANT)
------------------------------
- etc/userdb.txt must contain only **plain-text credentials** in the format:
      username:password
  Example:
      root:root
      admin:admin
      pi:raspberry
      ubuntu:ubuntu
- DO NOT use bcrypt, SHA, or hashed tokens — Cowrie's UserDB expects plain text.
- Include at least 3–5 common default credentials.

OTHER NOTES
------------
- No absolute paths or systemd service files should be generated.
- Keep file layout consistent with standard Cowrie install tree.

""".strip()

    return prompt


def generate_windows_prompt_from_profile(windows_profile: dict) -> str:
    """
    Generál egy OpenCanary-konfigurációs promptot a windows_profile.json alapján.
    Visszaad egy stringet, amit az LLM-nek adunk; a LLM-nek egyetlen fájlblokkot kell
    visszaadnia: --- FILE: opencanary.conf --- <JSON>.

    Fontos: a prompt kifejezetten tiltja a 'honeypot', 'canary', 'trap', 'deception' és
    hasonló kifejezések használatát a kimenetben, és kéri a reális Windows-szerver kinézetet.
    """
    # --- Basic data extraction from JSON (based on profile) ---
    hostname = windows_profile.get("hostname", "").strip() or "fileserver-01"
    domain = windows_profile.get("domain", "").strip() or "corp.local"
    interfaces = windows_profile.get("interfaces", ["eth0"])
    os_names = ", ".join(list(windows_profile.get("os_names", {}).keys())[:3]) or "Microsoft Windows Server 2022"
    os_versions = ", ".join(list(windows_profile.get("os_versions", {}).keys())[:3]) or "10.0.19045"
    open_ports = ", ".join(list(windows_profile.get("open_ports", {}).keys())[:6]) or "21, 80, 2222, 445, 3389"
    process_list = ", ".join(list(windows_profile.get("process_names", {}).keys())[:10]) or "svchost.exe, conhost.exe, powershell.exe"
    packages = ", ".join(list(windows_profile.get("package_names", {}).keys())[:10]) or "Microsoft Defender, IIS, PowerShell"
    services = list(windows_profile.get("services", {}).keys()) if isinstance(windows_profile.get("services"), dict) else []
    service_summary = ", ".join(services) if services else "smb, http, ftp, ssh, rdp"
    log_path = windows_profile.get("log_path", "/var/log/opencanary/opencanary.log")

    # Vulnerability preview (informational only)
    vuln_map = windows_profile.get("vulnerabilities", {}) or {}
    vuln_preview_list = []
    for cve, meta in list(vuln_map.items())[:5]:
        snippet = ""
        if isinstance(meta, dict) and meta.get("examples"):
            ex = meta["examples"][0]
            snippet = (ex.get("description","") or ex.get("condition",""))[:140].replace("\n"," ")
        vuln_preview_list.append(f"{cve} ({meta.get('count',0)}) - {snippet}")
    vuln_preview = "\n    ".join(vuln_preview_list) if vuln_preview_list else "None detected."

    # --- Prompt text ---
    prompt = f"""
You are an experienced Windows systems engineer responsible for producing a realistic, deployable OpenCanary configuration.
OUTPUT RULE: produce **ONLY** a single file block in this exact format (no extra text, no explanations):

--- FILE: opencanary.conf ---
{{ ... JSON object ... }}

Telemetry (derive values from these — prefer the observed values, do not invent conflicting facts):
- Hostname (preferred): {hostname}
- Domain (preferred): {domain}
- Interfaces: {', '.join(interfaces)}
- OS families observed: {os_names}
- OS versions observed: {os_versions}
- Typical open ports (sample): {open_ports}
- Typical processes: {process_list}
- Installed packages (examples): {packages}
- Observed services: {service_summary}
- Log path suggestion: {log_path}
- Top vulnerabilities (informational): 
    {vuln_preview}

REQUIREMENTS (MUST BE FOLLOWED):
1) Output ONLY the single file block: --- FILE: opencanary.conf --- followed immediately by a valid JSON object (no Markdown, no commentary, no extra file blocks).
2) **Do NOT use or output** any of these strings anywhere in the JSON or in any values: "honeypot", "canary", "trap", "deception", "fake". Replace them with neutral terms if present.
3) The JSON must be a syntactically valid OpenCanary configuration suitable for deployment (OpenCanary >= 0.7). Prefer Windows-like defaults and banners.
4) Use Linux-compatible log path: "/var/log/opencanary/opencanary.log".
5) Include these required top-level keys: "device.node_id", "device.hostname", "device.domain", "network.interfaces", "logging", "logger", "alerters".
6) Enable realistic Windows services based on telemetry (set true/false as observed): ftp, http, ssh, smb, rdp. Include plausible ports and banners (examples: "Microsoft-IIS/10.0", "Microsoft FTP Service", "SSH-2.0-OpenSSH_for_Windows_8.1", "Microsoft SMB Server 10.0.19045").
7) Include an "smb.config_path" set to "/etc/opencanary/smb.json" and set "smb.enabled" appropriately if SMB observed.
8) Provide an "alerters" list containing at least:
   - EmailAlerter with realistic but placeholder credentials (use "<REPLACE_WITH_SECRET>" for any secret),
   - ConsoleAlerter.
   Ensure email subject is neutral (e.g., "[Alert] <hostname>").
9) Ports: prefer non-privileged SSH port 2222 (if profile explicitly indicates 22 and you must match, use profile value; otherwise use 2222).
10) Do NOT include any fields that explicitly tag this node as a honeytrap (no metadata like "generated_by: canary_tool" etc.).
11) Keep the configuration concise and realistic — avoid overly verbose debugging sections.

FORMAT EXAMPLE (the LLM must follow this exact container syntax):
--- FILE: opencanary.conf ---
{{ 
    "device.node_id": "fileserver-01",
    "device.hostname": "fileserver-01",
    "device.domain": "corp.local",
    ...
}}

FINAL NOTES:
- Use the supplied telemetry values as the primary source of truth; when uncertain, prefer realistic Windows server defaults.
- The resulting JSON will be parsed and further post-processed by automation; ensure it is strictly valid JSON.

"""
    return prompt.strip()

