
import json
from wazuh.Authentication.Token_generate import generate_JWT_token
from wazuh.SysCollector.CollectSystemInventory import collect_all_syscollector
from preprocess.Clean_export import clean_wazuh_export
from preprocess.Separate_OS import split_by_os
from preprocess.Aggregate import aggregate_os_specific

# main.py for entry point of the project
if __name__=="__main__":


    token = generate_JWT_token()
    data = collect_all_syscollector(token)
    # Save raw Wazuh export data
    with open("resources/wazuh_export.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    # Clean, aggregate and preprocess the data for AI input
    clean_wazuh_export("resources/wazuh_export.json", "resources/cleaned.json")
    split_by_os("resources/cleaned.json", "resources/windows_agents.json", "resources/linux_agents.json")
    aggregate_os_specific("resources/windows_agents.json", "resources/windows_profile.json")
    aggregate_os_specific("resources/linux_agents.json", "resources/linux_profile.json")

    


    