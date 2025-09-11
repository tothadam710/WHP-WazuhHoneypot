
from wazuh.Authentication.Token_generate import generate_JWT_token
from wazuh.SysCollector.CollectSystemInventory import Collect_System_Data


if __name__=="__main__":


    token = generate_JWT_token()
    Collect_System_Data(token)
    print(Collect_System_Data(token))


    