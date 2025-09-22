
import json
from LLM.prompt_generator import generate_cowrie_prompt_detailed
from wazuh.Authentication.Token_generate import generate_JWT_token
from wazuh.SysCollector.CollectSystemInventory import collect_all_syscollector
from preprocess.Clean_export import clean_wazuh_export
from preprocess.Separate_OS import split_by_os
from preprocess.Aggregate import aggregate_os_specific
from LLM.cowrie_config_no_limit import call_llm, save_files_from_response
#from LLM.cowrie_config import call_llm, save_files_from_response


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

    # Példa használat:
# with open("wazuh_data.json") as f:
#     data = json.load(f)
# prompt = generate_cowrie_prompt_detailed(data)
# print(prompt)
    with open("resources/linux_profile.json") as f:
        linux_data = json.load(f)
    

    linux_prompt = generate_cowrie_prompt_detailed(linux_data)
    

    with open("resources/linux_cowrie_prompt.txt", "w", encoding="utf-8") as f:
        f.write(linux_prompt)
    linux_response = call_llm(linux_prompt)
    save_files_from_response(linux_response, output_dir="cowrie_linux_output")

    

 