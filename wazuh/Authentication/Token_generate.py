import os
import requests
from dotenv import load_dotenv



def generate_JWT_token():
    
    load_dotenv(dotenv_path=".env")
    API_URL = os.getenv("WAZUH_MANAGER")
    API_USER = os.getenv("WAZUH_USER")
    API_PASS = os.getenv("WAZUH_PASSWORD")
    print(os.getenv("WAZUH_MANAGER"))

    
    auth_response = requests.post(
        f"{API_URL}/security/user/authenticate",
        auth=(API_USER, API_PASS),
        headers={"Content-Type": "application/json"},
        verify=False
    )

    if auth_response.status_code != 200:
        print("Hiba a token lekérésekor:", auth_response.text)
        exit(1)

    token = auth_response.json()["data"]["token"]
    return token
