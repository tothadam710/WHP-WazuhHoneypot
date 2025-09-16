import json
# Functions to clean and preprocess the raw Wazuh export data
def clean_agent_data(agent_data):
    cleaned = {}

    # OS information
    if "os" in agent_data and agent_data["os"]:
        os_entry = agent_data["os"][0]
        cleaned["os"] = [{
            "os": os_entry.get("os", {}),
            "hostname": os_entry.get("hostname"),
            "architecture": os_entry.get("architecture"),
            "os_release": os_entry.get("os_release", os_entry.get("release")),
            "version": os_entry.get("version"),
            "sysname": os_entry.get("sysname")
        }]

    # Hardware
    if "hardware" in agent_data and agent_data["hardware"]:
        hw = agent_data["hardware"][0]
        cleaned["hardware"] = [{
            "cpu": hw.get("cpu", {}),
            "ram": hw.get("ram", {})
        }]

    # Netiface
    if "netiface" in agent_data:
        cleaned["netiface"] = []
        for iface in agent_data["netiface"]:
            cleaned["netiface"].append({
                "rx": iface.get("rx", {}),
                "tx": iface.get("tx", {}),
                "type": iface.get("type"),
                "adapter": iface.get("adapter"),
                "state": iface.get("state"),
                "name": iface.get("name"),
                "mac": iface.get("mac"),
                "mtu": iface.get("mtu")
            })

    # Netproto
    if "netproto" in agent_data:
        cleaned["netproto"] = []
        for proto in agent_data["netproto"]:
            cleaned["netproto"].append({
                "dhcp": proto.get("dhcp"),
                "type": proto.get("type"),
                "gateway": proto.get("gateway"),
                "iface": proto.get("iface")
            })

    # Hotfixes
    if "hotfixes" in agent_data:
        cleaned["hotfixes"] = [{"hotfix": h.get("hotfix")} for h in agent_data["hotfixes"]]

    # Packages
    if "packages" in agent_data:
        cleaned["packages"] = []
        for pkg in agent_data["packages"]:
            cleaned["packages"].append({
                "vendor": pkg.get("vendor"),
                "install_time": pkg.get("install_time"),
                "description": pkg.get("description"),
                "version": pkg.get("version"),
                "name": pkg.get("name"),
                "architecture": pkg.get("architecture"),
                "location": pkg.get("location")
            })

    # Processes
    if "processes" in agent_data:
        cleaned["processes"] = agent_data["processes"]

    # Ports
    if "ports" in agent_data:
        cleaned["ports"] = agent_data["ports"]

    # Vulnerabilities
    if "vulnerabilities" in agent_data:
        cleaned["vulnerabilities"] = agent_data["vulnerabilities"]

    return cleaned

def clean_wazuh_export(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    cleaned_data = {}
    for agent_id, agent_data in raw_data.items():
        cleaned_data[agent_id] = clean_agent_data(agent_data)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(cleaned_data, f, indent=2, ensure_ascii=False)

    print(f"Cleaned data saved to: {output_file}")

