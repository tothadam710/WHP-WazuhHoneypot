import json
def split_by_os(input_file, windows_file, linux_file):
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    windows_agents = {}
    linux_agents = {}

    for agent_id, agent_data in data.items():
        os_block = agent_data.get("os", [])
        if isinstance(os_block, list) and os_block:
            os_info = os_block[0].get("os", {})
            platform = os_info.get("platform", "").lower()

            if "linux" in platform or "ubuntu" in os_info.get("name", "").lower() or "centos" in os_info.get("name", "").lower():
                linux_agents[agent_id] = agent_data
            else: 
                windows_agents[agent_id] = agent_data

    with open(windows_file, "w", encoding="utf-8") as f:
        json.dump(windows_agents, f, indent=2, ensure_ascii=False)

    with open(linux_file, "w", encoding="utf-8") as f:
        json.dump(linux_agents, f, indent=2, ensure_ascii=False)

    print(f"Windows agentek mentve ide: {windows_file}")
    print(f"Linux agentek mentve ide: {linux_file}")

