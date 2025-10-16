# 🛡️ WHP — Wazuh Honeypot Project

An intelligent honeypot system that integrates **Wazuh** with custom Python components to detect, log, and analyze malicious activities across a monitored network environment.

---

## 📚 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Development Guide](#development-guide)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## 🧩 Overview

**WHP (Wazuh Honeypot Project)** provides a centralized environment for collecting and analyzing honeypot data.  
It combines **Wazuh**’s security event monitoring with Python-based automation and preprocessing to provide actionable insights on network threats.

The system is modular, allowing you to integrate custom logic for:
- Threat data processing  
- Log archiving and cleanup  
- Alert generation and forwarding (via Wazuh or external APIs)  
- Integration with tools like MQTT, OpenAI, or REST webhooks  

---

## 🚀 Features

- ✅ Collects and parses honeypot event data  
- 🧮 Cleans and processes log information automatically  
- 🔗 Integrates directly with **Wazuh** for alert correlation  
- 🌐 RESTful / MQTT interface support for automation  
- ⚙️ Configurable and modular design  
- 🧠 Optional AI-based enrichment using the OpenAI API  

---

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/tothadam710/WHP-WazuhHoneypot.git
   cd WHP-WazuhHoneypot
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Linux / macOS
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## ⚙️ Configuration

Configuration values can be defined via `.env` or YAML/JSON configuration files.  
Below are example snippets for common setups.

### `.env` example
```env
OPENAI_API_KEY=your_api_key_here
MQTT_BROKER=broker.example.com
WAZUH_MANAGER=wazuh.example.com
```

### `config.yaml` example
```yaml
mqtt:
  host: broker.example.com
  port: 1883

wazuh:
  host: wazuh.example.com
  port: 55000
```

---

## ▶️ Usage

Start the main honeypot process:
```bash
python main.py
```

Run the archive and cleanup routine manually:
```bash
python archive_and_cleanup.py
```

Modules inside `preprocess/` and `wazuh/` can also be executed independently, depending on your configuration.

---

## 🧱 Architecture

- **main.py** – orchestrates honeypot logic and module execution  
- **preprocess/** – handles data cleaning, normalization, and validation  
- **wazuh/** – manages communication and alerting via Wazuh  
- **archive_and_cleanup.py** – manages log rotation and cleanup  
- **config files** – store credentials and operational parameters  

Data flows through preprocessing → analysis → Wazuh integration → storage and alerting.

---

## 📦 Requirements

Core dependencies used in this project:

```
requests
python-dotenv
openai
```

*(For a complete list, see `requirements.txt`.)*

---

## 🧑‍💻 Development Guide

- Fork this repository and create feature branches (`feature/your-feature`)  
- Use descriptive commit messages  
- Add comments and docstrings to all new functions and modules  
- Run code formatting (e.g., `black`, `isort`) before pushing  
- Open pull requests for review  

---

## 🤝 Contributing

1. Fork this repository  
2. Create your feature branch  
3. Commit your changes  
4. Push to your branch  
5. Open a pull request  

Contributions are welcome for improving documentation, adding integrations, or refining threat-detection logic.

---

## 📄 License

This project is open-source and available under the **MIT License**.  
See the `LICENSE` file for full license text.

---

## 🙏 Acknowledgments

- Developed by **Ádám Tóth** ([@tothadam710](https://github.com/tothadam710))  
- Built using **Wazuh**, **Python**, and community-driven open-source tools  
- Special thanks to contributors and the cybersecurity research community  

---

> *"Building smarter defensive systems — one honeypot at a time."*
