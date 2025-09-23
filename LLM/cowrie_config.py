import openai
import json
import os
import re
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


def sanitize_filename(name: str) -> str:
    """
    Biztonságosan megtisztítja a fájlnevet:
    - levágja a " ---" maradványokat
    - eltávolít vezető / vagy \ jeleket
    - tiltja a '..' elemeket
    - kiszűri a tiltott karaktereket
    """
    # Levágjuk a záró --- jelölést, ha van
    name = re.sub(r"\s*-{2,}\s*$", "", name).strip()

    # Normálizálás
    name = os.path.normpath(name)

    # Tiltjuk a parent traversal-t és abszolút utakat
    if os.path.isabs(name) or ".." in name.split(os.path.sep):
        name = os.path.basename(name)

    # Windows meghajtó (C:\...) eltávolítása
    name = re.sub(r"^[A-Za-z]:[\\/]", "", name)

    # Tiltott karakterek helyett _
    name = re.sub(r"[<>:\"|?*\x00-\x1F]", "_", name)

    if not name:
        name = "unnamed_file"

    return name


def save_files_from_response(response: str, output_dir="cowrie_output"):
    """
    Feldolgozza az LLM kimenetet, fájlokat ment az output_dir alá.
    Várható formátum:
    --- FILE: path/to/file ---
    <tartalom>
    """
    os.makedirs(output_dir, exist_ok=True)

    # Regex: filename + tartalom
    pattern = re.compile(
        r"---\s*FILE:\s*(.+?)\s*---\s*\n(.*?)(?=(?:\n---\s*FILE:)|\Z)",
        re.DOTALL | re.IGNORECASE
    )

    found = list(pattern.finditer(response))
    if not found:
        print("⚠️ Nem találtam fájlblokkokat a válaszban.")
        return

    for m in found:
        raw_filename = m.group(1)
        content = m.group(2).rstrip("\n")

        # Több részes path engedélyezett (pl. etc/passwd)
        parts = [p for p in re.split(r"[\\/]+", raw_filename) if p]
        safe_parts = [sanitize_filename(p) for p in parts]

        target_path = os.path.join(output_dir, *safe_parts)
        target_path = os.path.normpath(target_path)

        # Biztonság: ne léphessen ki az output_dir-ből
        if not target_path.startswith(os.path.normpath(output_dir) + os.path.sep) \
           and target_path != os.path.normpath(output_dir):
            target_path = os.path.join(output_dir, sanitize_filename(raw_filename))

        target_dir = os.path.dirname(target_path)
        if target_dir and not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)

        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"✅ File created: {os.path.relpath(target_path)}")

