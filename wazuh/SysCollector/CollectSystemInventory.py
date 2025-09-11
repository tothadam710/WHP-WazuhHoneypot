import requests
import os
from dotenv import load_dotenv
import json

# --- Konfiguráció ---
ENDPOINTS = ["os","hardware","netiface","netproto","hotfixes","packages","processes","ports"]
DOTENV_PATH = "../../.env"

# --- Segédfüggvények ---
def load_config():
    load_dotenv(dotenv_path=DOTENV_PATH)
    API_URL = os.getenv("WAZUH_MANAGER")
    return API_URL

def get_agents(token):
    """Lekéri az összes agent id-t"""
    API_URL = load_config()
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{API_URL}/agents", headers=headers, verify=False)

    if response.status_code == 200:
        items = response.json().get("data", {}).get("affected_items", [])
        items.pop(0)
        return [item.get("id") for item in items]
    else:
        print("Hiba az agentek lekérdezésénél:", response.text)
        return []
    
def get_vulnerabilities(agent_id):
    ES_URL = os.getenv("Indexer")
    ES_USER = os.getenv("Indexer_user")
    ES_PASS = os.getenv("Indexer_password")
    """Lekéri az agenthez tartozó vulnerabilities-t Elasticsearchből GET + body"""
    query = {
        "_source": [
            "agent.name",
            "agent.id",
            "vulnerability.id",
            "vulnerability.description",
            "vulnerability.severity",
            "vulnerability.category",
            "vulnerability.detected_at",
            "vulnerability.published_at",
            "vulnerability.under_evaluation",
            "vulnerability.score",
            "vulnerability.scanner"
        ],
        "size": 10000,
        "query": {
            "bool": {
                "must": [
                    {"match": {"agent.id": agent_id}}
                ]
            }
        }
    }

    response = requests.get(
        f"{ES_URL}/wazuh-states-vulnerabilities-*/_search",
        auth=(ES_USER, ES_PASS),
        headers={"Content-Type": "application/json"},
        data=json.dumps(query),
        verify=False
    )

    if response.status_code == 200:
        hits = response.json().get("hits", {}).get("hits", [])
        print(hits)
        return [hit["_source"] for hit in hits]
    else:
        print(f"Hiba a vulnerabilities lekérdezésnél (agent {agent_id}):", response.text)
        return []

def get_syscollector_data(token, agent_id, endpoint):
    """Lekéri egy adott agent syscollector adatait"""
    API_URL = load_config()
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{API_URL}/syscollector/{agent_id}/{endpoint}", headers=headers, verify=False)

    if response.status_code == 200:
        return response.json().get("data", {}).get("affected_items", [])
    else:
        print(f"Hiba a syscollector lekérdezésnél (agent {agent_id}, endpoint {endpoint}):", response.text)
        return []
    

    


def collect_all_syscollector(token):
    """Összegyűjti minden agent syscollector adatait fix endpointokkal"""
    agents = get_agents(token)
    all_data = {}

    for agent_id in agents:
        all_data[agent_id] = {}
        for endpoint in ENDPOINTS:
            all_data[agent_id][endpoint] = get_syscollector_data(token, agent_id, endpoint)
        all_data[agent_id]["vulnerabilities"] = get_vulnerabilities(agent_id)
    return all_data


