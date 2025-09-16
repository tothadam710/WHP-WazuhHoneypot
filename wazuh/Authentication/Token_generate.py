import os
import requests
from dotenv import load_dotenv

# function to generate JWT token for Wazuh API authentication
# The connection details are loaded from system environment variables

def generate_JWT_token():
    
    load_dotenv(dotenv_path=".env")
    API_URL = os.getenv("WAZUH_MANAGER")
    API_USER = os.getenv("WAZUH_USER")
    API_PASS = os.getenv("WAZUH_PASSWORD")
    print(os.getenv("WAZUH_MANAGER"))

    #todo: handle certificate verification properly
    auth_response = requests.post(
        f"{API_URL}/security/user/authenticate",
        auth=(API_USER, API_PASS),
        headers={"Content-Type": "application/json"},
        verify=False
    )

    if auth_response.status_code != 200:
        print("Error during token retrieval:", auth_response.text)
        exit(1)

    token = auth_response.json()["data"]["token"]
    return token
