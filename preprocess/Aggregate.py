def aggregate_os_specific(input_file, output_file):
    import json
    from collections import Counter, defaultdict

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    os_versions = Counter()
    os_names = Counter()
    os_platforms = Counter()
    open_ports = Counter()
    process_names = Counter()
    package_names = Counter()
    cve_counter = Counter()
    cve_details = defaultdict(list)

    for agent in data.values():
        os_block = agent.get("os", [])
        if isinstance(os_block, list) and os_block:
            os_info = os_block[0].get("os", {})
            version = os_info.get("version")
            name = os_info.get("name")
            platform = os_info.get("platform")

            if version:
                os_versions[version] += 1
            if name:
                os_names[name] += 1
            if platform:
                os_platforms[platform] += 1

        for port in agent.get("ports", []):
            local = port.get("local", {})
            remote = port.get("remote", {})
            local_port = local.get("port")
            remote_port = remote.get("port")

            if local_port:
                open_ports[f"local:{local_port}"] += 1
            if remote_port and remote_port != 0:
                open_ports[f"remote:{remote_port}"] += 1

        for proc in agent.get("processes", []):
            name = proc.get("name")
            if name:
                process_names[name] += 1

        for pkg in agent.get("packages", []):
            name = pkg.get("name")
            if name:
                package_names[name] += 1

        for vuln in agent.get("vulnerabilities", []):
            v = vuln.get("vulnerability", {})
            cve = v.get("id")
            if cve:
                cve_counter[cve] += 1
                cve_details[cve].append({
                    "severity": v.get("severity"),
                    "score": v.get("score", {}).get("base"),
                    "version": v.get("score", {}).get("version"),
                    "description": v.get("description"),
                    "published_at": v.get("published_at"),
                    "condition": v.get("scanner", {}).get("condition"),
                    "source": v.get("scanner", {}).get("source"),
                    "reference": v.get("scanner", {}).get("reference"),
                    "category": v.get("category")
                })

    top_cves = dict()
    for cve, count in cve_counter.most_common(10):
        top_cves[cve] = {
            "count": count,
            "examples": cve_details[cve][:3]
        }

    profile = {
        "os_versions": dict(os_versions.most_common(10)),
        "os_names": dict(os_names.most_common(10)),
        "os_platforms": dict(os_platforms.most_common(10)),
        "open_ports": dict(open_ports.most_common(20)),
        "process_names": dict(process_names.most_common(15)),
        "package_names": dict(package_names.most_common(15)),
        "vulnerabilities": top_cves
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2, ensure_ascii=False)

    print(f"Profil mentve ide: {output_file}")
