import re
import math
from dataclasses import dataclass


@dataclass
class Finding:
    type: str
    severity: str
    matched: str
    pattern_name: str


def _mask(s: str) -> str:
    return s[:4] + "****" if len(s) > 4 else "****"


PATTERNS = [
    ("aws_access_key",       "high",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key",       "critical", re.compile(r"(?i)aws.?secret.{0,10}['\"\s=:]+([A-Za-z0-9/+]{40})")),
    ("gcp_api_key",          "high",     re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("github_token",         "high",     re.compile(r"gh[poas]_[A-Za-z0-9]{36,}")),
    ("private_key",          "critical", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt_token",            "high",     re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("bearer_token",         "high",     re.compile(r"Bearer ([A-Za-z0-9\-._~+/]+=*)")),
    ("db_connection_string", "high",     re.compile(r"(postgres|mysql|mongodb|redis):\/\/[^@\s]+:[^@\s]+@\S+")),
    ("ssn",                  "critical", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("azure_key",            "high",     re.compile(r"(?i)azure[\s\S]{0,100}[a-zA-Z0-9+/]{43}=")),
]


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

        return findings
