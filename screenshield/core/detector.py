import re
import math
from dataclasses import dataclass


@dataclass
class Finding:
    type: str
    severity: str
    matched: str
    pattern_name: str


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _luhn(digits: str) -> bool:
    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _mask(s: str) -> str:
    return s[:4] + "****" if len(s) > 4 else "****"


PATTERNS = [
    ("aws_access_key",       "high",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key",       "critical", re.compile(r"(?i)aws.?secret.{0,20}['\"\s=:]+([A-Za-z0-9/+]{40})")),
    ("gcp_api_key",          "high",     re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("github_token",         "high",     re.compile(r"gh[poas]_[A-Za-z0-9]{30,}")),
    ("private_key",          "critical", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt_token",            "high",     re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("bearer_token",         "high",     re.compile(r"Bearer ([A-Za-z0-9\-._~+/]+=*)")),
    ("db_connection_string", "high",     re.compile(r"(postgres|mysql|mongodb|redis):\/\/[^@\s]+:[^@\s]+@\S+")),
    ("ssn",                  "critical", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("azure_key",            "high",     re.compile(r"(?i)azure[\s\S]{0,100}[a-zA-Z0-9+/]{43}=")),
]

# credit card and env_variable handled separately below
_CC_RE = re.compile(r"\b(\d[\d\s\-]{11,17}\d)\b")
_ENV_RE = re.compile(r"([A-Z_]{4,})=(([\"']?)([^\s]{12,})\3)")


class Detector:
    def detect(self, text: str) -> list[Finding]:
        findings = []

        for name, severity, pat in PATTERNS:
            for m in pat.finditer(text):
                raw = m.group(0)
                findings.append(Finding(
                    type=name,
                    severity=severity,
                    matched=_mask(raw),
                    pattern_name=name,
                ))

        for m in _CC_RE.finditer(text):
            digits = re.sub(r"[\s\-]", "", m.group(1))
            if len(digits) < 13 or len(digits) > 19:
                continue
            # Luhn check catches most typos, worth the extra pass even on regex match
            if _luhn(digits):
                findings.append(Finding(
                    type="credit_card",
                    severity="critical",
                    matched=_mask(digits),
                    pattern_name="credit_card",
                ))

        for m in _ENV_RE.finditer(text):
            val = m.group(4)
            # threshold of 3.5 bits filters short low-entropy values like "localhost"
            if entropy(val) >= 3.5:
                findings.append(Finding(
                    type="env_variable",
                    severity="medium",
                    matched=f"{m.group(1)}=****",
                    pattern_name="env_variable",
                ))

        return findings
