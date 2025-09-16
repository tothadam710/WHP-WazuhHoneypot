import requests
import os
from dotenv import load_dotenv
import json

#env variables and constants for the module
ENDPOINTS = ["os","hardware","netiface","netproto","hotfixes","packages","processes","ports"]
DOTENV_PATH = "../../.env"

#load config from .env
def load_config():
    load_dotenv(dotenv_path=DOTENV_PATH)
    API_URL = os.getenv("WAZUH_MANAGER")
    return API_URL

# API call to get the list of agents with Token authentication
def get_agents(token):
    API_URL = load_config()
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{API_URL}/agents", headers=headers, verify=False)

    if response.status_code == 200:
        items = response.json().get("data", {}).get("affected_items", [])
        items.pop(0) #remove the first item which is wazuh manager itself
        return [item.get("id") for item in items]
    else:
        print("Error during agent retrieval:", response.text)
        return []
# Function to get vulnerabilities for a specific agent from Elasticsearch    
def get_vulnerabilities(agent_id):
    ES_URL = os.getenv("Indexer")
    ES_USER = os.getenv("Indexer_user")
    ES_PASS = os.getenv("Indexer_password")
   
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
    #API call to Elasticsearch to get vulnerabilities with basic auth
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
        print(f"Error during vulnerability retrieval (agent {agent_id}):", response.text)
        return []
# Function to get syscollector data for a specific agent and endpoint
def get_syscollector_data(token, agent_id, endpoint):
    
    API_URL = load_config()
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{API_URL}/syscollector/{agent_id}/{endpoint}", headers=headers, verify=False)

    if response.status_code == 200:
        return response.json().get("data", {}).get("affected_items", [])
    else:
        print(f"Error during syscollector retrieval (agent {agent_id}, endpoint {endpoint}):", response.text)
        return []
    

    

#Function to collect all syscollector data and vulnerabilities for all agents and return as a nested dictionary
def collect_all_syscollector(token):
    
    agents = get_agents(token)
    all_data = {}

    for agent_id in agents:
        all_data[agent_id] = {}
        for endpoint in ENDPOINTS:
            all_data[agent_id][endpoint] = get_syscollector_data(token, agent_id, endpoint)
        all_data[agent_id]["vulnerabilities"] = get_vulnerabilities(agent_id)
    return all_data


