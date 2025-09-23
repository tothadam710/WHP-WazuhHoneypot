import random
from datetime import datetime
from typing import Dict, Optional

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
        # make nginx-like worker label if nginx appears
        if "nginx" in name.lower():
            display_name = "nginx: worker process"
        # sanitize long kernel names minimally
        display_name = display_name.replace(" ", "_")
        for i in range(min(cnt, cap_per_proc)):
            pid += random.randint(1,120)
            # cpu/mem heuristics
            if any(x in name.lower() for x in ("mysql","mysqld","java")):
                cpu = round(random.uniform(3.0, 20.0),1)
                mem = round(random.uniform(3.0, 18.0),1)
            elif name.startswith("kworker") or name.startswith("khung") or name.startswith("kdev"):
                cpu = round(random.uniform(0.0, 3.0),1)
                mem = round(random.uniform(0.0, 1.0),1)
            elif "unattended" in name.lower():
                cpu = round(random.uniform(1.0, 8.0),1)
                mem = round(random.uniform(0.2, 2.0),1)
            else:
                cpu = round(random.uniform(0.0, 6.0),1)
                mem = round(random.uniform(0.1, 3.0),1)
            lines.append(f"{pid:>5} {display_name:<28} {cpu:>5}% {mem:>5}%")
    return "\n    ".join(lines)

def _format_package_preview(packages: Dict[str,int], max_show:int=12):
    """
    Build apt/dpkg-like preview lines referencing package names from inventory.
    Show installed lines and inject one plausible dpkg warning referencing an actual package.
    """
    pk_lines = []
    items = list(packages.items())[:max_show] if packages else []
    for pkg, count in items:
        # version is not present in your dict; show installed hint using count as pseudo-version hint
        pk_lines.append(f"{pkg} installed (meta-count={count})")
    if items:
        broken_pkg = items[min(2, len(items)-1)][0]
        pk_lines.append(f"dpkg: warning: while removing package {broken_pkg}: dependency problems - not fully installed (simulated)")
        pk_lines.append(f"apt: E: Sub-process /usr/bin/dpkg returned an error code (1) (simulated)")
    return "\n    ".join(pk_lines)

def generate_cowrie_prompt_detailed(wazuh_data: Dict, sample_zip: Optional[str]=None) -> str:
    """
    Produce a highly detailed prompt that embeds the exact package/process inventory
    from the provided `wazuh_data` dict so the LLM output mimics a host with those
    packages installed and those processes running.

    Returns a single prompt string ready to pass to an LLM. The LLM must output only
    file blocks (see instructions inside).
    """

    # Basic environment extraction with fallbacks
    os_names = ", ".join(wazuh_data.get("os_names", {}).keys()) if wazuh_data.get("os_names") else "Ubuntu"
    os_versions = ", ".join(wazuh_data.get("os_versions", {}).keys()) if wazuh_data.get("os_versions") else "16.04.7 LTS"
    platforms = ", ".join(wazuh_data.get("os_platforms", {}).keys()) if wazuh_data.get("os_platforms") else "x86_64"
    open_ports = ", ".join(wazuh_data.get("open_ports", {}).keys()) if wazuh_data.get("open_ports") else "22"

    processes = wazuh_data.get("process_names", {}) or {}
    packages = wazuh_data.get("package_names", {}) or {}
    vulnerabilities = (wazuh_data.get("vulnerabilities") or {}).keys()
    vuln_preview = ", ".join(list(vulnerabilities)[:8]) if vulnerabilities else "none"

    # Derive human-like usernames (if user list present else sensible defaults)
    # prefer to keep consistent names if some passwd/userdb files exist in sample_zip (not handled here)
    human_users = ["admin","deploy","git","ci-runner","ops","anna","peter","nora","kevin","maria"]
    # If passwd in sample_zip we might extract real users; omitted for brevity.

    # Build ps and package preview snippets inserted into the prompt (concrete examples)
    ps_preview = _format_ps_example(processes)
    pk_preview = _format_package_preview(packages)

    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    prompt = f"""
You are a senior on-call Linux sysadmin and intrusion analyst. Generate a set of **highly realistic** Cowrie honeypot filesystem artifacts.
**OUTPUT MUST BE ONLY file blocks**, in this exact format (nothing else):

--- FILE: <relative/path/to/file> ---
<file content>

Use the exact inventory below to make the artifacts look like they came from a real Ubuntu 16.04 host. The generated files must reference these package names and must contain ps/top snapshots consistent with the running processes counts.

ENVIRONMENT (use these values)
- OS Names: {os_names}
- OS Versions: {os_versions}
- Platform: {platforms}
- Open ports: {open_ports}

INSTALLED PACKAGES (use these package names in apt/dpkg-like outputs)
    {pk_preview}

RUNNING PROCESSES (ps/top style examples — reflect multiplicity, varied PIDs & usage)
    {ps_preview}

NOTABLE CVEs (observational only; do not produce exploit code): {vuln_preview}

MANDATORY FORMAT & SAFETY RULES
- DO NOT include working exploits, malware, or runnable payloads.
- DO NOT include any real credentials or real private keys.
- All hashes/tokens must be synthetic, random-looking strings (e.g. $6$... for /etc/shadow, $2y$... for userdb).
- Use RFC-3339 timestamps **without fractional seconds** (e.g. {now}).
- Output ONLY file blocks; nothing outside them.
- Keep files moderately sized (realistic, not enormous).

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
   - Ubuntu 16.04 style greeting including OS version and a "Last security update" date (simulated).
   - Include 1–2 management/documentation URLs.

5) --- FILE: cowrie.cfg ---
   - Realistic sections: [honeypot], [ssh], [shell], [output_jsonlog], [output_textlog].
   - listen_endpoints on port 22; include 1–2 commented alternate ports.
   - userdb_file -> etc/userdb.txt; log files in var/log/cowrie.
   - Add a couple admin comments/TODOs (typos acceptable). No private keys.

6) --- FILE: etc/userdb.txt ---
   - One bcrypt-like token per human user: format "user:$2y$10$<22-28 chars>"
   - Tokens should vary in length/appearance.

7) --- FILE: log/cowrie.log --- and --- FILE: log/auth.log ---
   - Use RFC5737 attacker IPs: 192.0.2.x, 198.51.100.x, 203.0.113.x.
   - Simulate a realistic attacker session:
       * repeated failed logins from one IP (use different usernames from /etc/passwd)
       * one successful login for a non-root user from another IP
       * cowrie.session lines: executed commands (id; uname -a; ps aux; cat /proc/cpuinfo | head -n1; sudo -l)
       * explicit session open/close lines (pam_unix session opened/closed)
       * interleave kernel/syslog noise: "TCP: Possible SYN flooding", "BUG: unable to handle kernel NULL pointer dereference", "Connection reset by peer", "broken pipe"
       * include ps/top snapshots that **use the exact process names** from the RUNNING PROCESSES snippet above (repeat worker entries with distinct PIDs)
       * when attacker inspects services (e.g., `systemctl status ufw`), include output that references the `ufw` package (or other packages listed)

8) --- FILE: logs/cve_simulation.log ---
   - One RFC-3339 timestamped line per CVE (use CVE IDs from input), each with a short observational symptom (no exploit code). Example format:
       2025-09-23T21:18:58Z CVE-2022-37434 — gzip header parsing failed; connection reset

EXTRA REALISM (strongly encouraged)
- Add a fabricated /proc/cpuinfo single-line: "model name : Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz"
- Add systemd/CRON noise: "Started Daily apt download activities", "CRON[1234]: pam_unix(cron:session): session opened for user root"
- In cowrie.cfg, keep a commented legacy banner or alternate listen_endpoints line.

NOW: produce **ONLY** the files requested above as file blocks with the described realism. Use the exact package/process names from the inventory when useful.
"""
    return prompt.strip()
