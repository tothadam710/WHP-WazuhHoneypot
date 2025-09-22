import os
import json
from dotenv import load_dotenv
from groq import Groq

# Betöltjük a .env fájlból az API kulcsot
load_dotenv(dotenv_path=".env")
groq_api_key = os.getenv("GROQ_API_KEY")

# Inicializáljuk a Groq klienst
client = Groq(api_key=groq_api_key)

def call_llm(prompt: str) -> str:
    response = client.chat.completions.create(
        model="qwen/qwen3-32b",  # Groq által támogatott Mistral modell
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )
    return response.choices[0].message.content

def save_files_from_response(response: str, output_dir="cowrie_output"):
    os.makedirs(output_dir, exist_ok=True)
    files = response.split("--- FILE:")
    for file_block in files[1:]:
        header, *content_lines = file_block.strip().split("\n")
        filename = header.strip()
        content = "\n".join(content_lines).strip()
        with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as f:
            f.write(content)
        print(f"✅ File created: {filename}")
