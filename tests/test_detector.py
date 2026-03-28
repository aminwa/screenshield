import pytest
from screenshield.core.detector import Detector, entropy


def test_aws_access_key():
    findings = Detector().detect("key = AKIAIOSFODNN7EXAMPLE")
    assert any(f.type == "aws_access_key" for f in findings)


def test_aws_secret_key():
    text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12"'
    findings = Detector().detect(text)
    assert any(f.type == "aws_secret_key" for f in findings)


def test_gcp_api_key():
    findings = Detector().detect("api_key=AIzaSyD1234567890abcdefghijklmnopqrstuvw")
    assert any(f.type == "gcp_api_key" for f in findings)


def test_github_token():
    findings = Detector().detect("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234")
    assert any(f.type == "github_token" for f in findings)


def test_private_key():
    findings = Detector().detect("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...")
    assert any(f.type == "private_key" for f in findings)


def test_jwt_token():
    # well-formed JWT header segment starts with eyJ
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = Detector().detect(token)
    assert any(f.type == "jwt_token" for f in findings)


def test_bearer_token():
    findings = Detector().detect("Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0")
    assert any(f.type == "bearer_token" for f in findings)


def test_db_connection_string():
    findings = Detector().detect("DATABASE_URL=postgres://admin:s3cr3t@db.example.com/mydb")
    assert any(f.type == "db_connection_string" for f in findings)


def test_env_variable():
    # high entropy value should be flagged
    findings = Detector().detect("SECRET_KEY=aB3$xQ9mZp2!wK7nYdRvLs")
    assert any(f.type == "env_variable" for f in findings)


def test_credit_card_visa():
    # 4111111111111111 is the canonical Luhn-valid test Visa number
    findings = Detector().detect("card: 4111111111111111")
    assert any(f.type == "credit_card" for f in findings)


def test_credit_card_invalid_rejected():
    # incremented last digit breaks Luhn
    findings = Detector().detect("card: 4111111111111112")
    assert not any(f.type == "credit_card" for f in findings)


def test_ssn():
    findings = Detector().detect("ssn: 123-45-6789")
    assert any(f.type == "ssn" for f in findings)


def test_azure_key():
    key = "A" * 43 + "="
    findings = Detector().detect(f"azure subscription key={key}")
    assert any(f.type == "azure_key" for f in findings)


def test_entropy_helper():
    assert entropy("aaaa") == 0.0
    assert entropy("ab") == 1.0
    assert entropy("") == 0.0


def test_masking():
    findings = Detector().detect("key = AKIAIOSFODNN7EXAMPLE")
    f = next(x for x in findings if x.type == "aws_access_key")
    assert f.matched.endswith("****")
    assert not f.matched.startswith("****")
