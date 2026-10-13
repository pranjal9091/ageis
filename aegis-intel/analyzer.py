"""
Aegis Threat Intelligence Engine
Shannon Entropy Analysis & Heuristic Risk Scoring for In-Flight Web Payloads
"""

import math
import re
from collections import Counter
from typing import Dict, Any

class ThreatAnalyzer:
    def __init__(self):
        self.sqli_pattern = re.compile(
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
            r"truncate\s+table|exec(\s|\+)+(s|x)p|sleep\s*\(\s*\d+\s*\)|--\s*$|'\s*or\s*['\d]+=['\d]+)"
        )
        self.xss_pattern = re.compile(
            r"(?i)(<script[^>]*>|javascript\s*:|onload\s*=|onerror\s*=|document\.cookie|<svg[^>]*onload=)"
        )
        self.traversal_pattern = re.compile(
            r"(?i)(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/proc/self|/boot\.ini)"
        )
        self.hex_escape_pattern = re.compile(r"(%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|&#x[0-9a-fA-F]+;)")

    def calculate_entropy(self, text: str) -> float:
        """
        Calculates Shannon Entropy: H(X) = -sum(P(x) * log2(P(x)))
        Normal plain-text English / JSON typically ranges from 2.8 to 4.5.
        High entropy (> 5.0) in short payloads indicates packed/obfuscated malicious code or base64 shellcode.
        """
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
        return round(entropy, 3)

    def analyze(self, payload: str, path: str = "", method: str = "GET", headers: Dict[str, str] = None) -> Dict[str, Any]:
        headers = headers or {}
        combined_text = f"{path} {payload} {' '.join(headers.values())}"
        
        entropy = self.calculate_entropy(payload or path)
        risk_score = 0
        signals = []

        # 1. Entropy anomaly scoring
        # Payloads longer than 15 chars with entropy > 4.9 are flagged
        if len(payload) > 15 and entropy > 4.85:
            risk_score += 35
            signals.append({
                "type": "HIGH_SHANNON_ENTROPY",
                "severity": "HIGH",
                "details": f"Payload entropy of {entropy} exceeds baseline (normal < 4.5). Indicates obfuscation/packing."
            })
        elif len(payload) > 10 and entropy < 1.8:
            risk_score += 20
            signals.append({
                "type": "LOW_ENTROPY_REPETITION",
                "severity": "MEDIUM",
                "details": f"Payload entropy of {entropy} indicates automated repetitive buffer fuzzer."
            })

        # 2. Hex / URL-encoded density
        hex_matches = self.hex_escape_pattern.findall(combined_text)
        if len(hex_matches) > 3:
            risk_score += 25
            signals.append({
                "type": "HIGH_ENCODING_DENSITY",
                "severity": "MEDIUM",
                "details": f"Detected {len(hex_matches)} encoded evasion sequences."
            })

        # 3. Signature Matching
        if self.sqli_pattern.search(combined_text):
            risk_score += 50
            signals.append({
                "type": "SQL_INJECTION_PATTERN",
                "severity": "CRITICAL",
                "details": "Payload matches SQL statement injection heuristic."
            })

        if self.xss_pattern.search(combined_text):
            risk_score += 45
            signals.append({
                "type": "CROSS_SITE_SCRIPTING",
                "severity": "HIGH",
                "details": "Payload matches client DOM injection / script payload."
            })

        if self.traversal_pattern.search(combined_text):
            risk_score += 40
            signals.append({
                "type": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "details": "Payload contains relative directory traversal sequence."
            })

        # Clamp score between 0 and 100
        final_score = min(100, max(0, risk_score))

        if final_score >= 70:
            classification = "CRITICAL_THREAT"
            action = "IMMEDIATE_DROP_AND_QUARANTINE"
        elif final_score >= 40:
            classification = "SUSPICIOUS_ANOMALY"
            action = "STEP_UP_CHALLENGE_OR_MFA"
        elif final_score >= 20:
            classification = "ELEVATED_RISK"
            action = "RATE_LIMIT_INSPECTION"
        else:
            classification = "BENIGN"
            action = "ALLOW_WITH_TELEMETRY"

        return {
            "risk_score": final_score,
            "shannon_entropy": entropy,
            "classification": classification,
            "recommended_action": action,
            "anomaly_signals": signals,
            "inspected_length": len(payload)
        }

if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    test_normal = '{"userId": 104, "action": "view_balance"}'
    test_attack = "' UNION SELECT password, null FROM admin_users; --"
    test_obfuscated = "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgA="
    
    print("Normal:", analyzer.analyze(test_normal))
    print("Attack:", analyzer.analyze(test_attack))
    print("Obfuscated:", analyzer.analyze(test_obfuscated))
