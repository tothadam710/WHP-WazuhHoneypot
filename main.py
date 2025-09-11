
import json
from wazuh.Authentication.Token_generate import generate_JWT_token
from wazuh.SysCollector.CollectSystemInventory import collect_all_syscollector


if __name__=="__main__":


    token = generate_JWT_token()
    data = collect_all_syscollector(token)
    
    with open("wazuh_export.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    


    