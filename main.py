
import json
from wazuh.Authentication.Token_generate import generate_JWT_token
from wazuh.SysCollector.CollectSystemInventory import collect_all_syscollector
from preprocess.Clean_export import clean_wazuh_export
#from preprocess.Aggregate import aggregate_honeypot_patterns, aggregate_os_specific
from preprocess.Separate_OS import split_by_os
from preprocess.Aggregate import aggregate_os_specific

if __name__=="__main__":


    token = generate_JWT_token()
    data = collect_all_syscollector(token)

    with open("Resources/wazuh_export.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    clean_wazuh_export("Resources/wazuh_export.json", "Resources/cleaned.json")
    split_by_os("Resources/cleaned.json", "Resources/windows_agents.json", "Resources/linux_agents.json")
    aggregate_os_specific("Resources/windows_agents.json", "Resources/windows_profile.json")
    aggregate_os_specific("Resources/linux_agents.json", "Resources/linux_profile.json")

    


    