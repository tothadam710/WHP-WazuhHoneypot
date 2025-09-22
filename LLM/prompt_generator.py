import json

def generate_cowrie_prompt_detailed(wazuh_data: dict) -> str:
    """
    Generates a highly detailed prompt for an LLM to create a Cowrie honeypot configuration,
    persona, and all necessary deployment files based on Wazuh OS, package, process,
    and detailed CVE data.
    """
    
    os_info = wazuh_data.get("os_names", {})
    os_versions = wazuh_data.get("os_versions", {})
    os_platforms = wazuh_data.get("os_platforms", {})
    open_ports = wazuh_data.get("open_ports", {})
    processes = wazuh_data.get("process_names", {})
    packages = wazuh_data.get("package_names", {})
    vulnerabilities = wazuh_data.get("vulnerabilities", {})

    # Dynamic OS/platform info
    os_summary = ", ".join([f"{name} {version}" for name, version in os_versions.items()])
    os_list = ", ".join(os_info.keys())
    platform_list = ", ".join(os_platforms.keys())
    
    # Processes and packages
    process_list = ", ".join(processes.keys())
    package_list = ", ".join(packages.keys())

    # Format detailed CVE information
    cve_details = []
    for cve, cve_data in vulnerabilities.items():
        examples = cve_data.get("examples", [])
        for example in examples:
            cve_details.append(
                f"- {cve} (Severity: {example['severity']}, Score: {example['score']})\n"
                f"  - Published: {example.get('published_at', 'Unknown')}\n"
                f"  - Affected Version: {example.get('version', 'Unknown')}\n"
                f"  - Condition: {example.get('condition', 'Unknown')}\n"
                f"  - Category: {example.get('category', 'Unknown')}\n"
                f"  - Source: {example.get('source', 'Unknown')}\n"
                f"  - Reference: {example.get('reference', 'Unknown')}\n"
                f"  - Description: {example.get('description', 'No description')}\n"
                f"  - Honeypot Simulation:\n"
                f"      - Simulate realistic exploit behavior corresponding to this CVE\n"
                f"      - Show errors, crashes, or anomalies consistent with affected version\n"
                f"      - Log all attempts in a realistic manner"
            )
    cve_text = "\n".join(cve_details)

    prompt = f"""
You are a cybersecurity expert tasked with configuring a Cowrie honeypot
to mimic a real system environment as closely as possible for threat intelligence collection.
Use the following OS, processes, packages, open ports, and detailed CVE information
to generate a highly realistic honeypot persona and configuration.

System Information:
- Operating Systems: {os_list} (versions: {os_summary}, platforms: {platform_list})
- Open Ports: {', '.join(open_ports.keys()) if open_ports else 'None'}
- Running Processes: {process_list}
- Installed Packages: {package_list}

Vulnerabilities (CVE) to simulate realistically:
{cve_text}

Instructions for the LLM:
1. Generate a Cowrie honeypot configuration that mimics this environment, including:
   - Appropriate SSH banner and login prompts
   - Realistic shell environment reflecting running processes
   - Installed package versions where feasible
   - Services listening on the specified ports
   - Behavioral quirks consistent with the OS and packages

2. Define a persona for the honeypot that attackers would expect:
   - Typical usernames
   - Directory structures
   - Commonly used commands
   - Simulated vulnerable behavior aligned with the CVEs listed

3. Include CVE-based behavior simulation:
   - For each CVE, describe how the honeypot should respond if an attacker attempts an exploit
   - Simulate errors, crashes, or information leaks where appropriate, without compromising the host
   - Focus on realism and engagement for threat intelligence purposes

4. Generate all necessary deployment files for Cowrie, including:
   - cowrie.cfg
   - userdb.txt with usernames and hashed passwords
   - etc/passwd and etc/shadow for system users
   - etc/hostname and etc/motd for realistic login messages
   - log/ directory for CVE simulation logging
   - Scripts or commands for safely simulating CVE exploits

Output each file separately with clear file headers, e.g.:

--- FILE: cowrie.cfg ---
<content>

--- FILE: userdb.txt ---
<content>

Ensure all files are consistent with each other and the persona you defined. Include realistic CVE behavior in logs or scripts.
"""
    return prompt.strip()
