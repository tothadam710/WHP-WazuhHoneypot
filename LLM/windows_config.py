import openai
import json
import os
import re
from dotenv import load_dotenv

# --- ENV betöltése ---
load_dotenv(dotenv_path=".env")
openai.api_key = os.getenv("OPENAI_API_KEY")

# --- LLM hívás ---
def call_llm(prompt: str) -> str:
    """
    Meghívja az OpenAI LLM-et (GPT-5 modellt) a megadott prompttal
    és visszaadja a nyers szöveges választ.
    """
    response = openai.ChatCompletion.create(
        model="gpt-5",
        messages=[{"role": "user", "content": prompt}],
        # temperature=0.7   # opcionális
    )
    return response["choices"][0]["message"]["content"]

# --- Segédfüggvény: fájlnév biztonságosítás ---
def sanitize_filename(name: str) -> str:
    """
    Biztonságosan megtisztítja a fájlnevet (Windows-profilhoz):
    - levágja a " ---" maradványokat
    - eltávolítja a meghajtójeleket (C:\ stb.)
    - tiltja a '..' elemeket
    - kiszűri a tiltott karaktereket
    """
    name = re.sub(r"\s*-{2,}\s*$", "", name).strip()
    name = os.path.normpath(name)

    # Parent traversal tiltás
    if os.path.isabs(name) or ".." in name.split(os.path.sep):
        name = os.path.basename(name)

    # Windows meghajtó (C:\...) eltávolítása
    name = re.sub(r"^[A-Za-z]:[\\/]", "", name)

    # Tiltott karakterek helyettesítése _
    name = re.sub(r"[<>:\"|?*\x00-\x1F]", "_", name)

    if not name:
        name = "unnamed_file"

    return name

# --- Fő függvény: fájlok mentése az LLM-válaszból ---
def save_files_from_response(response: str, output_dir="windows_output"):
    """
    Feldolgozza az LLM kimenetet (Windows-profilhoz), és fájlokat ment az output_dir alá.
    Várható formátum:
        --- FILE: path/to/file ---
        <tartalom>
    """
    os.makedirs(output_dir, exist_ok=True)

    pattern = re.compile(
        r"---\s*FILE:\s*(.+?)\s*---\s*\n(.*?)(?=(?:\n---\s*FILE:)|\Z)",
        re.DOTALL | re.IGNORECASE,
    )

    matches = list(pattern.finditer(response))
    if not matches:
        print("⚠️ Nem találtam fájlblokkokat a válaszban.")
        return

    for match in matches:
        raw_filename = match.group(1).strip()
        content = match.group(2).rstrip("\n")

        # Szétszedjük az útvonalat Windows és Unix szeparátorok mentén
        parts = [p for p in re.split(r"[\\/]+", raw_filename) if p]
        safe_parts = [sanitize_filename(p) for p in parts]

        target_path = os.path.join(output_dir, *safe_parts)
        target_path = os.path.normpath(target_path)

        # Biztonság: ne lépjen ki az output_dir-ből
        base = os.path.normpath(output_dir)
        if not target_path.startswith(base + os.path.sep) and target_path != base:
            target_path = os.path.join(base, sanitize_filename(raw_filename))

        target_dir = os.path.dirname(target_path)
        if target_dir and not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)

        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"✅ File created: {os.path.relpath(target_path)}")
        


