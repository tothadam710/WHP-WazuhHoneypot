import openai
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file

load_dotenv(dotenv_path=".env")

# Set the API key
openai.api_key = os.getenv("OPENAI_API_KEY")
print(openai.api_key)

def call_llm(prompt: str) -> str:
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )
    return response['choices'][0]['message']['content']

def save_files_from_response(response: str, output_dir="cowrie_output"):
    os.makedirs(output_dir, exist_ok=True)
    files = response.split("--- FILE:")
    for file_block in files[1:]:
        header, *content_lines = file_block.strip().split("\n")
        filename = header.strip()
        content = "\n".join(content_lines).strip()
        with open(os.path.join(output_dir, filename), "w") as f:
            f.write(content)
        print(f"✅ File created: {filename}")