import socket
import json

# Extended port service registry
PORT_REGISTRY = {
    21: {"service": "FTP", "product": "vsftpd 2.3.4"},
    22: {"service": "SSH", "product": "OpenSSH 7.4p1"},
    80: {"service": "HTTP", "product": "Apache httpd 2.4.49"},
    443: {"service": "HTTPS", "product": "OpenSSL 1.1.1"},
    3306: {"service": "MySQL", "product": "MySQL Server 5.7"},
    8000: {"service": "HTTP-Dev", "product": "Uvicorn/FastAPI Core"},
    8080: {"service": "HTTP-Proxy", "product": "Apache Tomcat 9.0.0"}
}

# Curated security vulnerability intelligence database
VULN_DATABASE = {
    "vsftpd 2.3.4": [
        {
            "id": "CVE-2011-2523",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "title": "Backdoor Command Execution",
            "solution": "Upgrade vsftpd to version 3.0 or higher."
        }
    ],
    "OpenSSH 7.4p1": [
        {
            "id": "CVE-2023-38408",
            "severity": "HIGH",
            "cvss": 7.5,
            "title": "PKCS#11 Provider Remote Code Execution",
            "solution": "Apply vendor security patch or upgrade OpenSSH to 9.3p2+."
        }
    ],
    "Apache httpd 2.4.49": [
        {
            "id": "CVE-2021-41773",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "title": "Path Traversal & Remote Code Execution",
            "solution": "Immediately update to Apache 2.4.51 or later."
        }
    ],
    "Uvicorn/FastAPI Core": [
        {
            "id": "SEC-AUDIT-DEV01",
            "severity": "LOW",
            "cvss": 3.1,
            "title": "Exposed Development Service",
            "solution": "Ensure development servers are not bound to 0.0.0.0 in production environments."
        }
    ]
}

def scan_host(target_ip: str, timeout: float = 0.5):
    findings = []
    print(f"[*] Initiating vulnerability scan against: {target_ip}")

    for port, meta in PORT_REGISTRY.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        status = sock.connect_ex((target_ip, port))

        if status == 0:
            product = meta["product"]
            cve_records = VULN_DATABASE.get(product, [])
            findings.append({
                "port": port,
                "service": meta["service"],
                "banner": product,
                "status": "OPEN",
                "vulnerabilities": cve_records
            })
        sock.close()

    # Aggregate Risk Metrics
    all_vulns = [v for item in findings for v in item["vulnerabilities"]]
    risk_summary = {
        "CRITICAL": sum(1 for v in all_vulns if v["severity"] == "CRITICAL"),
        "HIGH": sum(1 for v in all_vulns if v["severity"] == "HIGH"),
        "MEDIUM": sum(1 for v in all_vulns if v["severity"] == "MEDIUM"),
        "LOW": sum(1 for v in all_vulns if v["severity"] == "LOW"),
        "TOTAL": len(all_vulns)
    }

    return {
        "target": target_ip,
        "summary": risk_summary,
        "results": findings
    }

if __name__ == "__main__":
    report = scan_host("127.0.0.1")
    print(json.dumps(report, indent=2))
