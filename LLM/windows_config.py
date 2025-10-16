import openai
import json
import os
import re
import random
from dotenv import load_dotenv
from pathlib import Path

# --- Load ENV ---
load_dotenv(dotenv_path=".env")
openai.api_key = os.getenv("OPENAI_API_KEY")

# --- LLM call (simple wrapper) ---
def call_llm(prompt: str) -> str:
    """
    Meghívja az OpenAI LLM-et (GPT-5 modellt) a megadott prompttal
    és visszaadja a nyers szöveges választ.
    """
    response = openai.ChatCompletion.create(
        model="gpt-5",
        messages=[{"role": "user", "content": prompt}],
    )
    return response["choices"][0]["message"]["content"]

# --- Filename sanitization ---
def sanitize_filename(name: str) -> str:
    name = re.sub(r"\s*-{2,}\s*$", "", name).strip()
    name = os.path.normpath(name)
    if os.path.isabs(name) or ".." in name.split(os.path.sep):
        name = os.path.basename(name)
    name = re.sub(r"^[A-Za-z]:[\\/]", "", name)
    name = re.sub(r"[<>:\"|?*\x00-\x1F]", "_", name)
    if not name:
        name = "unnamed_file"
    return name

# -----------------------------
# Random hostname/domain generator
# -----------------------------
_HOST_PREFIXES = ["web", "app", "db", "file", "mail", "print", "proxy", "auth", "hr", "backup"]
_DOMAINS = ["corp.local", "office.local", "internal.lan", "company.local", "intra.local"]

def generate_random_hostname(seed: int = None) -> str:
    rnd = random.Random(seed) if seed is not None else random
    prefix = rnd.choice(_HOST_PREFIXES)
    num = rnd.randint(1, 99)
    style = rnd.choice(["simple", "env"])
    if style == "env":
        env = rnd.choice(["prod", "dev", "stg", "qa"])
        return f"{prefix}-{env}-{num:02d}"
    return f"{prefix}-{num:02d}"

def generate_random_domain(seed: int = None) -> str:
    rnd = random.Random(seed) if seed is not None else random
    return rnd.choice(_DOMAINS)

# -----------------------------
# SMB json generator
# -----------------------------
def generate_smb_json(profile: dict = None) -> dict:
    """
    Create a simple smb.json share description derived from profile if available.
    """
    default_shares = {
        "C$": {"comment": "System volume", "files": ["Windows", "Users", "Program Files"]},
        "ADMIN$": {"comment": "Administration share", "files": ["System32", "Temp"]},
        "Users": {"comment": "User profiles", "files": ["Administrator", "Public"]}
    }

    shares = default_shares.copy()
    if isinstance(profile, dict):
        for name, meta in (profile.get("smb_shares") or {}).items():
            nm = re.sub(r"[^A-Za-z0-9\-\_\\$]", "", name) or "Share"
            shares[nm] = {
                "comment": meta.get("comment", "Shared folder"),
                "files": meta.get("files", ["README.txt", "data"])
            }

    smb_conf = {
        "shares": shares,
        "allow_guest": bool(profile.get("smb_allow_guest", False)) if isinstance(profile, dict) else False,
        "default_user": (profile.get("smb_default_user") if isinstance(profile, dict) else "guest") or "guest"
    }
    return smb_conf

def save_smb_json(smb_conf: dict, output_path: str):
    outp = Path(output_path)
    if outp.is_dir():
        outp = outp / "smb.json"
    outp.parent.mkdir(parents=True, exist_ok=True)
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(smb_conf, f, indent=4)
    return str(outp)

# -----------------------------
# JSON cleaner / disguiser
# -----------------------------
def _clean_config_for_realism(config: dict, randomize_identity: bool = True, random_seed: int = None) -> dict:
    """
    Normalize/clean the LLM-produced JSON to the exact deploy-ready schema we want,
    remove any explicit honeypot/canary markers, ensure consistent keys, and set RDP cookie to hostname.
    """
    # Basic sanitization: remove explicit trap words
    text = json.dumps(config)
    text = re.sub(r"(?i)honeypot", "server", text)
    text = re.sub(r"(?i)canary", "srv", text)
    text = re.sub(r"(?i)trap|deception|fake", "", text)
    cfg = json.loads(text)

    # Identity selection
    if randomize_identity:
        hostname = generate_random_hostname(seed=random_seed)
        domain = generate_random_domain(seed=random_seed)
    else:
        hostname = cfg.get("device.hostname") or cfg.get("device.node_id") or "fileserver-01"
        domain = cfg.get("device.domain") or "company.local"

    # normalize hostname/domain
    hostname = re.sub(r"[^A-Za-z0-9\-\_\.]", "-", str(hostname)).strip("-")
    domain = re.sub(r"[^A-Za-z0-9\-\_\.]", "-", str(domain)).strip("-")

    cfg["device.hostname"] = hostname
    cfg["device.node_id"] = hostname
    cfg["device.domain"] = domain

    # Ensure listen addr exists (non-sensitive)
    cfg.setdefault("device.listen_addr", "0.0.0.0")

    # Logging normalization
    log_path = (cfg.get("logging") or {}).get("path") or (cfg.get("logging") or {}).get("logfile") or "/var/log/opencanary/opencanary.log"
    cfg["logging"] = {
        "type": "file",
        "level": (cfg.get("logging") or {}).get("level", "INFO"),
        "path": log_path
    }

    # Logger normalized
    backupCount = 5
    try:
        backupCount = int(((cfg.get("logger") or {}).get("kwargs") or {}).get("handlers", {}).get("file", {}).get("backupCount") or 5)
    except Exception:
        backupCount = 5

    cfg["logger"] = {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": {"format": "%(asctime)s %(levelname)s %(message)s"}
            },
            "handlers": {
                "file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "filename": log_path,
                    "maxBytes": 10485760,
                    "backupCount": backupCount
                },
                "console": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout"
                }
            }
        }
    }

    # Alerters normalization: try to extract email config from config if present
    email_host = "smtp.corp.local"
    email_port = 587
    email_user = f"alerts@{domain}"
    email_pass = "<REPLACE_WITH_SECRET>"
    email_from = f"alerts@{domain}"
    email_to = [f"soc@{domain}"]
    email_tls = True

    for a in (config.get("alerters") or []):
        if not isinstance(a, dict):
            continue
        # detect email-like entries
        keys = " ".join(a.keys()).lower()
        if "email" in keys or "host" in keys or "to" in keys or "smtp" in keys:
            # try nested kwargs first
            kwargs = a.get("kwargs", {}) if isinstance(a.get("kwargs", {}), dict) else {}
            email_host = kwargs.get("host") or a.get("host") or email_host
            email_port = kwargs.get("port") or a.get("port") or email_port
            email_user = kwargs.get("username") or kwargs.get("user") or a.get("username") or a.get("user") or email_user
            email_pass = kwargs.get("password") or a.get("password") or email_pass
            email_from = kwargs.get("fromaddr") or a.get("from") or a.get("fromaddr") or email_from
            email_to = kwargs.get("toaddrs") or a.get("to") or a.get("toaddrs") or email_to
            email_tls = bool(kwargs.get("tls") if "tls" in kwargs else a.get("tls", email_tls))

    cfg["alerters"] = [
        {
            "class": "EmailAlerter",
            "enabled": True,
            "kwargs": {
                "host": email_host,
                "port": int(email_port),
                "username": email_user,
                "password": email_pass,
                "tls": bool(email_tls),
                "fromaddr": email_from,
                "toaddrs": email_to,
                "subject": f"[Alert] {hostname}"
            }
        },
        {
            "class": "ConsoleAlerter",
            "enabled": True,
            "kwargs": {}
        }
    ]

    # Services normalization and defaults
    def get_from(orig, *keys, default=None):
        for k in keys:
            if isinstance(orig, dict) and k in orig:
                return orig[k]
        return default

    cfg["ftp.enabled"] = bool(get_from(config, "ftp.enabled", default=config.get("ftp.enabled", True)))
    cfg["ftp.port"] = int(get_from(config, "ftp.port", default=21) or 21)
    cfg["ftp.banner"] = get_from(config, "ftp.banner", default="220 Microsoft FTP Service")

    cfg["http.enabled"] = bool(get_from(config, "http.enabled", default=config.get("http.enabled", True)))
    cfg["http.port"] = int(get_from(config, "http.port", default=80) or 80)
    cfg["http.skin"] = get_from(config, "http.skin", default="basic")
    cfg["http.banner"] = get_from(config, "http.banner", default="Microsoft-IIS/10.0")

    cfg["ssh.enabled"] = bool(get_from(config, "ssh.enabled", default=config.get("ssh.enabled", True)))
    orig_ssh = get_from(config, "ssh.port", default=config.get("ssh.port"))
    cfg["ssh.port"] = int(orig_ssh) if orig_ssh else 2222
    cfg["ssh.version"] = get_from(config, "ssh.version", default="SSH-2.0-OpenSSH_for_Windows_8.1")

    cfg["smb.enabled"] = bool(get_from(config, "smb.enabled", default=config.get("smb.enabled", True)))
    cfg["smb.port"] = int(get_from(config, "smb.port", default=445) or 445)
    # unify domain to uppercase to match earlier examples
    cfg["smb.domain"] = str(get_from(config, "smb.domain", default=domain)).upper()
    # machine name
    cfg["smb.machine_name"] = str(get_from(config, "smb.machine_name", default=hostname)).upper()
    cfg["smb.banner"] = get_from(config, "smb.banner", default=f"Microsoft SMB Server {config.get('os_version','10.0.19044')}")
    cfg["smb.share_name"] = get_from(config, "smb.share_name", default="C$")
    cfg["smb.config_path"] = get_from(config, "smb.config_path", default="/etc/opencanary/smb.json")

    cfg["rdp.enabled"] = bool(get_from(config, "rdp.enabled", default=config.get("rdp.enabled", True)))
    cfg["rdp.port"] = int(get_from(config, "rdp.port", default=3389) or 3389)
    # set RDP cookie to hostname to avoid mismatch
    cfg["rdp.cookie"] = f"mstshash={hostname}"

    # Flags
    cfg["portscan.enabled"] = True
    cfg["smtp.enabled"] = False
    cfg["telnet.enabled"] = False

    # Human-friendly services block
    cfg["services"] = {
        "ftp.banner": cfg.get("ftp.banner"),
        "http.banner": cfg.get("http.banner"),
        "ssh.version": cfg.get("ssh.version"),
        "smb.share_name": cfg.get("smb.share_name"),
        "rdp.banner": "Remote Desktop Protocol 10.0"
    }

    return cfg

# -----------------------------
# File extraction from LLM response
# -----------------------------
def save_files_from_response(response: str, output_dir="windows_output"):
    os.makedirs(output_dir, exist_ok=True)

    pattern = re.compile(
        r"---\s*FILE:\s*(.+?)\s*---\s*\n(.*?)(?=(?:\n---\s*FILE:)|\Z)",
        re.DOTALL | re.IGNORECASE,
    )

    matches = list(pattern.finditer(response))
    if not matches:
        print("⚠️ Nem találtam fájlblokkokat a válaszban.")
    else:
        for match in matches:
            raw_filename = match.group(1).strip()
            content = match.group(2).rstrip("\n")

            parts = [p for p in re.split(r"[\\/]+", raw_filename) if p]
            safe_parts = [sanitize_filename(p) for p in parts]
            target_path = os.path.join(output_dir, *safe_parts)
            target_path = os.path.normpath(target_path)

            base = os.path.normpath(output_dir)
            if not target_path.startswith(base + os.path.sep) and target_path != base:
                target_path = os.path.join(base, sanitize_filename(raw_filename))

            target_dir = os.path.dirname(target_path)
            if target_dir and not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)

            with open(target_path, "w", encoding="utf-8") as f:
                f.write(content)

            print(f"✅ File created: {os.path.relpath(target_path)}")

# -----------------------------
# Opencanary.conf generator from prompt
# -----------------------------
def generate_opencanary_from_prompt(prompt_path="windows_prompt.txt", output_dir="windows_output", randomize_identity: bool = True, random_seed: int = None, profile: dict = None):
    """
    Beolvassa a windows_prompt.txt-t, elküldi az LLM-nek,
    elmenti a fileblokkokat (pl. smb.json, egyéb), kinyeri a JSON-t,
    tisztítja/normalizálja, beállítja RDP cookie-t hostname-re,
    generál egy smb.json-t (ha nincs LLM által hozott), majd elmenti mindet.
    Returns path to opencanary.conf on success, else None.
    """
    if not os.path.exists(prompt_path):
        raise FileNotFoundError(f"❌ Nem található a prompt fájl: {prompt_path}")

    with open(prompt_path, "r", encoding="utf-8") as f:
        prompt = f.read()

    print("📤 LLM hívás folyamatban...")
    llm_response = call_llm(prompt)
    print("📥 Válasz megérkezett az LLM-től.")

    # 1) Save any files from the response first
    save_files_from_response(llm_response, output_dir=output_dir)

    # 2) Extract JSON block
    json_match = re.search(r"\{.*\}", llm_response, re.DOTALL)
    if not json_match:
        print("⚠️ Nem találtam JSON konfigurációt a válaszban.")
        return None

    json_text = json_match.group(0)
    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError as e:
        print(f"⚠️ JSON parse hiba: {e}")
        return None

    # 3) Clean/normalize the JSON
    final_conf = _clean_config_for_realism(parsed, randomize_identity=randomize_identity, random_seed=random_seed)

    # 4) Save opencanary.conf
    os.makedirs(output_dir, exist_ok=True)
    conf_path = os.path.join(output_dir, "opencanary.conf")
    with open(conf_path, "w", encoding="utf-8") as f:
        json.dump(final_conf, f, indent=4)
    print(f"✅ Realisztikus opencanary.conf létrehozva: {conf_path}")

    # 5) Generate smb.json if not already present
    # Check if smb.json already exists in output_dir (was saved from LLM)
    smb_output_candidate = Path(output_dir) / "smb.json"
    if smb_output_candidate.exists():
        print(f"ℹ️ smb.json megtalálva a LLM válaszában: {smb_output_candidate}")
    else:
        smb_conf = generate_smb_json(profile or {})
        saved = save_smb_json(smb_conf, output_dir)
        print(f"✅ SMB config generálva és elmentve: {saved}")

    return conf_path
