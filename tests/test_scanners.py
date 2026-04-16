"""
SecureAI Platform — Scanner Tests
===================================
TDD proof that every scanner works correctly.

Three categories:
1. Clean projects pass — no false positives
2. Vulnerable projects fail — detections work
3. Edge cases handled — no crashes on bad input
"""

import os
import pytest
import tempfile
from secureai.scanners.docker import DockerScanner
from secureai.scanners.secrets import SecretsScanner


# ── DOCKER SCANNER TESTS ─────────────────────────────────────────────

class TestDockerScanner:
    """Tests for the Docker security scanner."""

    def test_clean_dockerfile_passes(self, tmp_path):
        """
        A hardened Dockerfile should produce zero HIGH findings.
        This proves the scanner has no false positives on good code.
        """
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM python:3.12-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y gcc
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runtime
WORKDIR /app
RUN groupadd --gid 1001 appgroup && \\
    useradd --uid 1001 --gid appgroup --no-create-home appuser
COPY --from=builder /usr/local /usr/local
USER appuser
HEALTHCHECK --interval=30s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
        """)

        scanner = DockerScanner(path=str(tmp_path))
        findings = scanner.scan()

        high_and_above = [
            f for f in findings
            if f["severity"] in ("CRITICAL", "HIGH")
        ]
        assert len(high_and_above) == 0, (
            f"Clean Dockerfile produced HIGH/CRITICAL findings: {high_and_above}"
        )

    def test_missing_user_directive_flagged(self, tmp_path):
        """
        A Dockerfile without USER directive must be flagged as HIGH.
        Running as root is a critical security misconfiguration.
        """
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM python:3.12-slim
WORKDIR /app
COPY . .
CMD ["python", "app.py"]
        """)

        scanner = DockerScanner(path=str(tmp_path))
        findings = scanner.scan()

        severities = [f["severity"] for f in findings]
        assert "HIGH" in severities, (
            "Missing USER directive should be flagged as HIGH"
        )

    def test_hardcoded_password_in_compose_flagged(self, tmp_path):
        """
        Hardcoded credentials in docker-compose.yml must be CRITICAL.
        This is the #1 thing interviewers check for.
        """
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("""
services:
  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_PASSWORD=mysecretpassword
    healthcheck:
      test: ["CMD", "pg_isready"]
      interval: 10s
      timeout: 5s
      retries: 5
        """)

        scanner = DockerScanner(path=str(tmp_path))
        findings = scanner.scan()

        severities = [f["severity"] for f in findings]
        assert "CRITICAL" in severities, (
            "Hardcoded password should be flagged as CRITICAL"
        )

    def test_env_var_reference_not_flagged(self, tmp_path):
        """
        Proper env var references like ${POSTGRES_PASSWORD}
        must NOT be flagged — they are safe.
        """
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("""
services:
  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    healthcheck:
      test: ["CMD", "pg_isready"]
      interval: 10s
      timeout: 5s
      retries: 5
        """)

        scanner = DockerScanner(path=str(tmp_path))
        findings = scanner.scan()

        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(critical) == 0, (
            "Environment variable references should not be flagged"
        )

    def test_privileged_container_flagged(self, tmp_path):
        """
        Privileged containers must be flagged as CRITICAL.
        Privileged mode grants full host system access.
        """
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("""
services:
  app:
    image: myapp:latest
    privileged: true
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 10s
      timeout: 5s
      retries: 5
        """)

        scanner = DockerScanner(path=str(tmp_path))
        findings = scanner.scan()

        severities = [f["severity"] for f in findings]
        assert "CRITICAL" in severities, (
            "Privileged container should be flagged as CRITICAL"
        )

    def test_floating_image_tag_flagged(self, tmp_path):
        """
        Images without sha256 digest pinning must be flagged.
        Floating tags can change without warning — supply chain risk.
        """
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("""
services:
  db:
    image: postgres:16-alpine
    healthcheck:
      test: ["CMD", "pg_isready"]
      interval: 10s
      timeout: 5s
      retries: 5
        """)

        scanner = DockerScanner(path=str(tmp_path))
        findings = scanner.scan()

        titles = [f["title"] for f in findings]
        assert any("Floating image tag" in t for t in titles), (
            "Floating image tag should be flagged"
        )

    def test_digest_pinned_image_not_flagged(self, tmp_path):
        """
        Images pinned to sha256 digest must NOT be flagged.
        This is the correct supply chain security practice.
        """
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("""
services:
  db:
    image: postgres@sha256:20edbde7749f822887a1a022ad526fde0a47d6b2be9a8364433605cf65099416
    healthcheck:
      test: ["CMD", "pg_isready"]
      interval: 10s
      timeout: 5s
      retries: 5
        """)

        scanner = DockerScanner(path=str(tmp_path))
        findings = scanner.scan()

        floating = [f for f in findings if "Floating image tag" in f["title"]]
        assert len(floating) == 0, (
            "Digest-pinned image should not be flagged as floating"
        )


# ── SECRETS SCANNER TESTS ────────────────────────────────────────────

class TestSecretsScanner:
    """Tests for the secrets detection scanner."""

    def test_clean_file_passes(self, tmp_path):
        """
        A file with no secrets should produce zero findings.
        """
        pyfile = tmp_path / "clean.py"
        pyfile.write_text("""
import os

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
API_KEY = os.getenv("API_KEY")

def connect():
    return DATABASE_URL
        """)

        scanner = SecretsScanner(path=str(tmp_path))
        findings = scanner.scan()
        assert len(findings) == 0, (
            f"Clean file should have no findings: {findings}"
        )

    def test_hardcoded_password_detected(self, tmp_path):
        """
        Hardcoded passwords in Python files must be detected.
        """
        pyfile = tmp_path / "config.py"
        pyfile.write_text("""
DATABASE_URL = "postgresql://admin:supersecretpassword@localhost/db"
        """)

        scanner = SecretsScanner(path=str(tmp_path))
        findings = scanner.scan()
        assert len(findings) > 0, (
            "Hardcoded database URL with password should be detected"
        )

    def test_aws_access_key_detected(self, tmp_path):
        pyfile = tmp_path / "aws_config.py"
        # Break the string so the scanner doesn't flag the test file itself
        key_prefix = "AKIA"
        fake_key = f"{key_prefix}IOSFODNN7EXAMPLE" 
    
        pyfile.write_text(f'AWS_ACCESS_KEY = "{fake_key}"')
    
        scanner = SecretsScanner(path=str(tmp_path))
        findings = scanner.scan()

        severities = [f["severity"] for f in findings]
        assert "CRITICAL" in severities, (
            "AWS access key should be detected as CRITICAL"
        )

    def test_env_example_skipped(self, tmp_path):
        """
        .env.example files must never be flagged.
        They contain placeholder values by design.
        """
        env_example = tmp_path / ".env.example"
        env_example.write_text("""
POSTGRES_PASSWORD=your-password-here
SECRET_KEY=your-secret-key-here
API_KEY=your-api-key-here
        """)

        scanner = SecretsScanner(path=str(tmp_path))
        findings = scanner.scan()
        assert len(findings) == 0, (
            ".env.example should never be flagged"
        )

    def test_venv_directory_skipped(self, tmp_path):
        """
        .venv directory must be skipped entirely.
        Third-party libraries may contain test keys.
        """
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        venv_file = venv_dir / "test_keys.py"
        venv_file.write_text("""
TEST_KEY = "AKIAIOSFODNN7EXAMPLE"
        """)

        scanner = SecretsScanner(path=str(tmp_path))
        findings = scanner.scan()
        assert len(findings) == 0, (
            ".venv directory should be skipped"
        )